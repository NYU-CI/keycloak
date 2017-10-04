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

package org.keycloak.authentication.requiredactions;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.common.util.Time;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.PasswordCredentialProvider;
import org.keycloak.credential.PasswordCredentialProviderFactory;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.*;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.resources.AccountService;
import org.keycloak.services.validation.Validation;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class UpdatePassword implements RequiredActionProvider, RequiredActionFactory {
    private static final Logger logger = Logger.getLogger(UpdatePassword.class);
    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        int daysToExpirePassword = context.getRealm().getPasswordPolicy().getDaysToExpirePassword();
        if(daysToExpirePassword != -1) {
            PasswordCredentialProvider passwordProvider = (PasswordCredentialProvider)context.getSession().getProvider(CredentialProvider.class, PasswordCredentialProviderFactory.PROVIDER_ID);
            CredentialModel password = passwordProvider.getPassword(context.getRealm(), context.getUser());
            if (password != null) {
                if(password.getCreatedDate() == null) {
                    context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                    logger.debug("User is required to update password");
                } else {
                    long timeElapsed = Time.toMillis(Time.currentTime()) - password.getCreatedDate();
                    long timeToExpire = TimeUnit.DAYS.toMillis(daysToExpirePassword);

                    if(timeElapsed > timeToExpire) {
                        context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
                        logger.debug("User is required to update password");
                    }
                }
            }
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        Response challenge = context.form()
                .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
        context.challenge(challenge);
    }

    @Override
    public void processAction(RequiredActionContext context) {
        EventBuilder event = context.getEvent();
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        event.event(EventType.UPDATE_PASSWORD);
        String password = formData.getFirst("password");
        String passwordNew = formData.getFirst("password-new");
        String passwordConfirm = formData.getFirst("password-confirm");

        EventBuilder errorEvent = event.clone().event(EventType.UPDATE_PASSWORD_ERROR)
                .client(context.getClientSession().getClient())
                .user(context.getClientSession().getUserSession().getUser());

        boolean requireCurrent = AccountService.isPasswordSet(context.getSession(), context.getRealm(), context.getUser());
        Boolean isLdapUser = Boolean.FALSE;
        if (context.getUser().getFederationLink() != null) {
            for(UserFederationProviderModel provider : context.getRealm().getUserFederationProviders()) {
                if(context.getUser().getFederationLink().equals(provider.getId()) && LDAPConstants.LDAP_PROVIDER.equals(provider.getProviderName())) {
                    isLdapUser = Boolean.TRUE;
                }
            }
        }

        if (isLdapUser && requireCurrent) {
            if (Validation.isBlank(password)) {
                Response challenge = context.form()
                        .setError(Messages.MISSING_PASSWORD)
                        .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                context.challenge(challenge);
                errorEvent.error(Errors.PASSWORD_MISSING);
                return;
            }

            UserCredentialModel cred = UserCredentialModel.password(password);
            if (!context.getSession().userCredentialManager().isValid(context.getRealm(), context.getUser(), cred)) {
                Response challenge = context.form()
                        .setError(Messages.INVALID_PASSWORD_EXISTING)
                        .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
                context.challenge(challenge);
                errorEvent.error(Errors.INVALID_USER_CREDENTIALS);
                return;
            }
        }

        if (Validation.isBlank(passwordNew)) {
            Response challenge = context.form()
                    .setError(Messages.MISSING_PASSWORD)
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_MISSING);
            return;
        } else if (!passwordNew.equals(passwordConfirm)) {
            Response challenge = context.form()
                    .setError(Messages.NOTMATCH_PASSWORD)
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            errorEvent.error(Errors.PASSWORD_CONFIRM_ERROR);
            return;
        }

        try {
            context.getSession().userCredentialManager().updateCredential(context.getRealm(), context.getUser(), UserCredentialModel.password(password, passwordNew));
            context.success();
        } catch (ModelException me) {
            String message = me.getMessage();
            if (me.getCause() != null && me.getCause().getMessage() != null) {
                Pattern pattern = Pattern.compile("\\[LDAP: error code 19 - (.*?)\\]");
                Matcher matcher = pattern.matcher(me.getCause().getMessage());
                if (matcher.find()) {
                    message = matcher.group(1);
                }
            }
            errorEvent.detail(Details.REASON, message).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setError(message, me.getParameters())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        } catch (Exception ape) {
            errorEvent.detail(Details.REASON, ape.getMessage()).error(Errors.PASSWORD_REJECTED);
            Response challenge = context.form()
                    .setError(ape.getMessage())
                    .createResponse(UserModel.RequiredAction.UPDATE_PASSWORD);
            context.challenge(challenge);
            return;
        }
    }

    @Override
    public void close() {

    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getDisplayText() {
        return "Update Password";
    }


    @Override
    public String getId() {
        return UserModel.RequiredAction.UPDATE_PASSWORD.name();
    }
}
