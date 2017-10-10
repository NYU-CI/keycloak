/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.federation.ldap.mappers.ppolicy;

import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.federation.ldap.LDAPFederationProvider;
import org.keycloak.federation.ldap.idm.model.LDAPObject;
import org.keycloak.federation.ldap.idm.query.internal.LDAPQuery;
import org.keycloak.federation.ldap.mappers.AbstractLDAPFederationMapper;
import org.keycloak.federation.ldap.mappers.PasswordUpdated;
import org.keycloak.models.*;
import org.keycloak.models.utils.UserModelDelegate;

import javax.naming.AuthenticationException;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Mapper specific to Open LDAP Password Policy. It's able to read the pwdAccountLockedTime and pwdReset attributes and set actions in Keycloak based on that.
 * It's also able to handle exception code from LDAP user authentication
 *
 * @author <a href="mailto:rafa.ladis@gmail.com">Rafael Ladislau</a>
 */
public class PPolicyUserAccountControlMapper extends AbstractLDAPFederationMapper implements PasswordUpdated {

    private static final Logger logger = Logger.getLogger(PPolicyUserAccountControlMapper.class);

    private static final Pattern AUTH_EXCEPTION_EXPIRED = Pattern.compile("Your password has expired");
    private static final Pattern AUTH_EXCEPTION_RESET = Pattern.compile("Your password must be changed after being reset");
    private static final Pattern AUTH_EXCEPTION_LOCKED = Pattern.compile("Account is locked");

    public PPolicyUserAccountControlMapper(UserFederationMapperModel mapperModel, LDAPFederationProvider ldapProvider, RealmModel realm) {
        super(mapperModel, ldapProvider, realm);
        ldapProvider.setUpdater(this);
    }

    @Override
    public void beforeLDAPQuery(LDAPQuery query) {
        query.addReturningLdapAttribute(LDAPConstants.PWD_RESET);
        query.addReturningLdapAttribute(LDAPConstants.PWD_ACCOUNT_LOCKED_TIME);

        // This needs to be read-only and can be set to writable just on demand
        query.addReturningReadOnlyLdapAttribute(LDAPConstants.PWD_RESET);

        if (ldapProvider.getEditMode() != UserFederationProvider.EditMode.WRITABLE) {
            query.addReturningReadOnlyLdapAttribute(LDAPConstants.PWD_ACCOUNT_LOCKED_TIME);
        }
    }

    @Override
    public void passwordUpdated(UserModel user, LDAPObject ldapUser, CredentialInput input) {
        logger.debugf("Going to remove the attribulte pwdReset for ldap user '%s' after successful password update", ldapUser.getDn().toString());
        // Usually Open LDAP update the control attributes when the password is updated
        // Normally it's read-only
/*        ldapUser.removeReadOnlyAttributeName(LDAPConstants.PWD_RESET);

        ldapUser.setSingleAttribute(LDAPConstants.PWD_LAST_SET, "-1");
        ldapUser.r

        UserAccountControl control = getUserAccountControl(ldapUser);
        control.remove(UserAccountControl.PASSWD_NOTREQD);
        control.remove(UserAccountControl.PASSWORD_EXPIRED);

        if (user.isEnabled()) {
            control.remove(UserAccountControl.ACCOUNTDISABLE);
        }

        updateUserAccountControl(ldapUser, control);*/
    }

    @Override
    public UserModel proxy(LDAPObject ldapUser, UserModel delegate) {
        return new PPolicyUserModelDelegate(delegate, ldapUser);
    }

    @Override
    public void onRegisterUserToLDAP(LDAPObject ldapUser, UserModel localUser) {

    }

    @Override
    public void onImportUserFromLDAP(LDAPObject ldapUser, UserModel user, boolean isCreate) {

    }

    @Override
    public boolean onAuthenticationFailure(LDAPObject ldapUser, UserModel user, AuthenticationException ldapException) {
        String exceptionMessage = ldapException.getMessage();
        Matcher m_expired = AUTH_EXCEPTION_EXPIRED.matcher(exceptionMessage);
        Matcher m_reset = AUTH_EXCEPTION_RESET.matcher(exceptionMessage);
        Matcher m_locked = AUTH_EXCEPTION_LOCKED.matcher(exceptionMessage);
        if (m_expired.matches() || m_reset.matches() || m_locked.matches()) {
            logger.debugf("Ppolicy Error code is '%s' after failed LDAP login of user '%s'", exceptionMessage, user.getUsername());

            if (ldapProvider.getEditMode() == UserFederationProvider.EditMode.WRITABLE) {
                if (m_expired.matches() || m_reset.matches()) {
                    user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                    return true;
                } else if (m_locked.matches()) {
                    // User is disabled in LDAP. Set him to disabled in KC as well
                    user.setEnabled(false);
                    return true;
                }
            }
            return false;
        } else {
            return false;
        }
    }


    public class PPolicyUserModelDelegate extends UserModelDelegate {

        private final LDAPObject ldapUser;

        public PPolicyUserModelDelegate(UserModel delegate, LDAPObject ldapUser) {
            super(delegate);
            this.ldapUser = ldapUser;
        }

        @Override
        public boolean isEnabled() {
            boolean kcEnabled = super.isEnabled();

            String pwdAccountLockedTime = ldapUser.getAttributeAsString(LDAPConstants.PWD_ACCOUNT_LOCKED_TIME);
            return kcEnabled && !( pwdAccountLockedTime != null && !pwdAccountLockedTime.isEmpty());

        }

        @Override
        public void setEnabled(boolean enabled) {
            // Always update DB
            super.setEnabled(enabled);

            if (ldapProvider.getEditMode() == UserFederationProvider.EditMode.WRITABLE) {
                logger.debugf("Going to propagate enabled=%s for ldapUser '%s' to LDAP", enabled, ldapUser.getDn().toString());

                if (enabled){
                    ldapUser.setAttribute(LDAPConstants.PWD_ACCOUNT_LOCKED_TIME, LDAPConstants.ATTRIBUTE_TO_BE_REMOVED);
                } else {

                    ldapUser.setSingleAttribute(LDAPConstants.PWD_ACCOUNT_LOCKED_TIME, "000001010000Z");
                }

                ldapProvider.getLdapIdentityStore().update(ldapUser);

            }
        }

        @Override
        public void addRequiredAction(RequiredAction action) {
            String actionName = action.name();
            addRequiredAction(actionName);
        }

        @Override
        public void addRequiredAction(String action) {
            // Always update DB
            super.addRequiredAction(action);

            if (ldapProvider.getEditMode() == UserFederationProvider.EditMode.WRITABLE && RequiredAction.UPDATE_PASSWORD.toString().equals(action)) {
                logger.debugf("Going to propagate required action UPDATE_PASSWORD to LDAP for ldap user '%s' ", ldapUser.getDn().toString());

                // Normally it's read-only
                ldapUser.removeReadOnlyAttributeName(LDAPConstants.PWD_RESET);

                ldapUser.setSingleAttribute(LDAPConstants.PWD_RESET, Boolean.TRUE.toString().toUpperCase());
                ldapProvider.getLdapIdentityStore().update(ldapUser);
            }
        }

        @Override
        public void removeRequiredAction(RequiredAction action) {
            String actionName = action.name();
            removeRequiredAction(actionName);
        }

        @Override
        public void removeRequiredAction(String action) {
            // Always update DB
            super.removeRequiredAction(action);

            if (ldapProvider.getEditMode() == UserFederationProvider.EditMode.WRITABLE && RequiredAction.UPDATE_PASSWORD.toString().equals(action)) {

                logger.debugf("Going to remove required action UPDATE_PASSWORD from LDAP for ldap user '%s' ", ldapUser.getDn().toString());

                // Normally it's read-only
                ldapUser.removeReadOnlyAttributeName(LDAPConstants.PWD_RESET);

                ldapUser.setAttribute(LDAPConstants.PWD_RESET, LDAPConstants.ATTRIBUTE_TO_BE_REMOVED);
                ldapProvider.getLdapIdentityStore().update(ldapUser);

            }
        }

        @Override
        public Set<String> getRequiredActions() {
            Set<String> requiredActions = super.getRequiredActions();

            if (ldapProvider.getEditMode() == UserFederationProvider.EditMode.WRITABLE) {
                if (getPwdReset()) {
                    requiredActions = new HashSet<>(requiredActions);
                    requiredActions.add(RequiredAction.UPDATE_PASSWORD.toString());
                    return requiredActions;
                }
            }

            return requiredActions;
        }

        protected Boolean getPwdReset() {
            String pwdReset = ldapUser.getAttributeAsString(LDAPConstants.PWD_RESET);
            return pwdReset == null ? Boolean.FALSE : Boolean.parseBoolean(pwdReset);
        }


    }

}
