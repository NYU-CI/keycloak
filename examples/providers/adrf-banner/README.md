Authenticator ADRF Banner
===================================================

1. First, build keycloak (mvn install -Pdistribution [-DskipTests])

2. Copy the jar file (./examples/providers/adrf-banner/target/authenticator-adrf-banner.jar) to the providers folder of keycloak (prod)

3. Copy the adrf-banner.ftl files to the themes/base/login directory.

4. Restart Keycloak.

5. Go to the Authentication menu item and go to the Flow tab, you will be able to view the currently
   defined flows.  You cannot modify an built in flows, so, to add the Authenticator you
   have to copy an existing flow or create your own.  Copy the "Browser" flow.

6. In your copy, in the Forms Auth Type, click the "Actions" menu (last column in the right) item and "Add Execution".  Pick ADRF Banner as Required.

7. Next you have to bind the new flow you created to the Browser Flow. Click on the Bind tab in the Authentication menu.
   Choose your new Flow as the Browser Flow and Save it.
   Now Keycloak will show your banner in all authetications by Form.

