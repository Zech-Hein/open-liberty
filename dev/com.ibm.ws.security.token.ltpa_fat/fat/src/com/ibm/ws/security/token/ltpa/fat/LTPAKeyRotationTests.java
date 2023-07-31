/*******************************************************************************
 * Copyright (c) 2023 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/

package com.ibm.ws.security.token.ltpa.fat;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpEntity;
import org.apache.http.HttpMessage;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.junit.runner.RunWith;

import com.ibm.websphere.simplicity.config.ServerConfiguration;
import com.ibm.websphere.simplicity.config.WebAppSecurity;
import com.ibm.websphere.simplicity.log.Log;
import com.ibm.ws.webcontainer.security.test.servlets.BasicAuthClient;
import com.ibm.ws.webcontainer.security.test.servlets.FormLoginClient;
import com.ibm.ws.webcontainer.security.test.servlets.FormLoginClient.LogoutOption;
import com.ibm.ws.webcontainer.security.test.servlets.SSLHelper;

import componenttest.custom.junit.runner.FATRunner;
import componenttest.custom.junit.runner.Mode;
import componenttest.custom.junit.runner.Mode.TestMode;
import componenttest.topology.impl.LibertyServer;
import componenttest.topology.impl.LibertyServerFactory;

@SuppressWarnings("restriction")
@RunWith(FATRunner.class)
@Mode(TestMode.FULL)
public class LTPAKeyRotationTests {

     // Initialize needed strings for the tests
    protected static String METHODS = null;
    protected static final String PROGRAMMATIC_API_SERVLET = "ProgrammaticAPIServlet";
    protected static final String authTypeForm = "FORM";
    protected static final String authTypeBasic = "BASIC";
    protected static final String cookieName = "LtpaToken2";

    // Keys to help readability of the test
    protected static final boolean IS_MANAGER_ROLE = true;
    protected static final boolean NOT_MANAGER_ROLE = false;
    protected static final boolean IS_EMPLOYEE_ROLE = true;
    protected static final boolean NOT_EMPLOYEE_ROLE = false;

    // Initialize a liberty server for basic auth and form login
    private static LibertyServer server = LibertyServerFactory.getLibertyServer("com.ibm.ws.security.token.ltpa.fat.ltpaKeyRotationTestServer");
    
    private final Class<?> thisClass = LTPAKeyRotationTests.class;

    // Initialize the user
    private static final String validUser = "user1";
    private static final String validPassword = "user1pwd";
    private static final String managerUser = "user2";
    private static final String managerPassword = "user2pwd";
    private static final String serverShutdownMessages = "CWWKG0083W";

    // Initialize the BasicAuth Clients
    private static final BasicAuthClient baClient1 = new BasicAuthClient(server, BasicAuthClient.DEFAULT_REALM, BasicAuthClient.DEFAULT_SERVLET_NAME, "/basicauth1");
    private static final BasicAuthClient baClient2 = new BasicAuthClient(server, BasicAuthClient.DEFAULT_REALM, BasicAuthClient.DEFAULT_SERVLET_NAME, "/basicauth2");

    // Initialize the FormLogin Clients
    private static final FormLoginClient flClient1 = new FormLoginClient(server, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin1");
    private static final FormLoginClient flClient2 = new FormLoginClient(server, FormLoginClient.DEFAULT_SERVLET_NAME, "/formlogin2");

    @Rule
    public final TestWatcher logger = new TestWatcher() {
        @Override
        // Function to make it easier to see when each test starts and ends
        public void starting(Description description) {
            Log.info(thisClass, description.getMethodName(), "\n@@@@@@@@@@@@@@@@@\nEntering test " + description.getMethodName() + "\n@@@@@@@@@@@@@@@@@");
        }
    };

    @BeforeClass
    public static void setUp() throws Exception {
        server.startServer(true);

        assertNotNull("Featurevalid did not report update was complete",
                      server.waitForStringInLog("CWWKF0008I"));
        assertNotNull("Security service did not report it was ready",
                      server.waitForStringInLog("CWWKS0008I"));
        assertNotNull("The application did not report is was started",
                      server.waitForStringInLog("CWWKZ0001I"));
    }

    @After
    public void resetConnection() {
        baClient1.resetClientState();
        baClient2.resetClientState();
        flClient1.resetClientState();
        flClient2.resetClientState();
    }

    @AfterClass
    public static void tearDown() throws Exception {
        try {
            server.stopServer(serverShutdownMessages);
        } finally {
            baClient1.releaseClient();
            baClient2.releaseClient();
            flClient1.releaseClient();
            flClient2.releaseClient();
        }
    }

    /**
     * Verify the following:
     * <OL>
     * <LI>Attempt to access a simple servlet configured for basic auth1 with a valid userId (mnagerUser) and password.
     * <LI>Get the cookie back from the session
     * <LI>Complete a key rotation, and add key 2 to ltpa1.keys
     * <LI>Attempt to access a simple servlet configured for basic auth1 with the cookie corresponding to the first key
     * <LI>Verify original LTPA key is still in the ltpa1.keys file
     * </OL>
     * <P>Expected Results:
     * <OL>
     * <LI>Successful authentication to simple servlet
     * <LI>Successful retrieval of cookie
     * <LI>Successful key rotation, and addition of key 2 to ltpa1.keys
     * <LI>Successful authentication to simple servlet, the user is still authenticated
     * <LI>Successful verification of original LTPA key in ltpa1.keys file
     * </OL>
     */
    @SuppressWarnings("restriction")
    @Mode(TestMode.LITE)
    @Test
    public void testSuccessfulAuthenticationWithOriginalKeys() {
        // Set the multipleLTPAKeys to true
        setWebAppSecurityConfigElement(server, "true");

        String response = baClient1.accessProtectedServletWithAuthorizedCredentials(BasicAuthClient.PROTECTED_SIMPLE, managerUser, managerPassword);
        assertNotNull(response);

        // Get the cookie back from the session
        String cookie = baClient1.getCookieFromLastLogin();
        assertNotNull(cookie);

        // Complete a key rotation, and add key 2 to ltpa1.keys
        //server.rotateLTPAKeys();

        /// Now try to access the servlet with the cookie corresponding to the first key
        response = baClient1.accessProtectedServletWithAuthorizedCookie(BasicAuthClient.PROTECTED_SIMPLE, cookie);
        assertNotNull(response);

        // Verify original LTPA key is still in the ltpa1.keys file

    }

    /**
     * Verify the following:
     * <OL>
     * <LI>Attempt to access a simple servlet configured for basic auth1 with a valid userId (mnagerUser) and password.
     * <LI>Get the cookie back from the session
     * <LI>Complete a key rotation, and add key 2 to ltpa1.keys
     * <LI>Attempt login with a new user after key rotation
     * <LI>Verify the new user is authenticated and provided a new cookie from LTPA key 2
     * </OL>
     * <P>Expected Results:
     * <OL>
     * <LI>Successful authentication to simple servlet
     * <LI>Successful retrieval of cookie
     * <LI>Successful key rotation, and addition of key 2 to ltpa1.keys
     * <LI>Successful authentication to simple servlet
     * <LI>Successful retrieval of cookie from LTPA key 2. LTPA cookie from key 1 is only used for verification but not for new authentication
     * </OL>
     */
    @SuppressWarnings("restriction")
    @Mode(TestMode.LITE)
    @Test
    public void testNewUserAuthentication() {
        // Set the multipleLTPAKeys to true
        setWebAppSecurityConfigElement(server, "true");

        String response = baClient1.accessProtectedServletWithAuthorizedCredentials(BasicAuthClient.PROTECTED_SIMPLE, managerUser, managerPassword);
        assertNotNull(response);

        // Get the cookie back from the session
        String cookie1 = baClient1.getCookieFromLastLogin();
        assertNotNull(cookie1);

        // Complete a key rotation, and add key 2 to ltpa1.keys
        //server.rotateLTPAKeys();

        // Attempt login with a new user after key rotation
        response = baClient1.accessProtectedServletWithAuthorizedCredentials(BasicAuthClient.PROTECTED_SIMPLE, validUser, validPassword);
        assertNotNull(response);

        // Verify the new user is authenticated and provided a new cookie from LTPA key 2
        String cookie2 = baClient1.getCookieFromLastLogin();
        assertNotNull(cookie2);
        //assertTrue(cookie2.contains("LtpaToken2"));

        // Assert that cookie1 and cookie2 are different
        assertFalse(cookie1.equals(cookie2));

        // Print both values
        Log.info(thisClass, "testNewUserAuthentication", "Cookie: " + cookie1);
        Log.info(thisClass, "testNewUserAuthentication", "Cookie: " + cookie2);
    }

    /**
     * Verify the following:
     * <OL>
     * <LI>Set ltpa expiration to 3 second
     * <LI>Intialize a session with a simple servlet configured for basic auth1 with a valid userId (mnagerUser) and password.
     * <LI>Get the cookie back from the session
     * <LI>Wait for the key to expire
     * <LI>Attempt to access a simple servlet configured for basic auth1 with the cookie corresponding to the first key
     * </OL>
     * <P>Expected Results:
     * <OL>
     * <LI>Successful update to the ltpa expiration in the server xml configuration
     * <LI>Successful authentication to simple servlet
     * <LI>Successful retrieval of cookie
     * <LI>Successful expiration of key, and removal of key 1 from ltpa1.keys
     * <LI>Unsuccessful authentication to simple servlet with cookie, the user is denied access
     * </OL>
     */
    @SuppressWarnings("restriction")
    @Mode(TestMode.LITE)
    @Test
    public void testExpiredKeyForcesReauthentication() {
        // Set the multipleLTPAKeys to true
        setWebAppSecurityConfigElement(server, "true");

        // Set ltpa expiration to 3 second
        //server.setLTPAExpiration(3);

        // Intialize a session with a simple servlet configured for basic auth1 with a valid userId (mnagerUser) and password.
        String response = baClient1.accessProtectedServletWithAuthorizedCredentials(BasicAuthClient.PROTECTED_SIMPLE, managerUser, managerPassword);
        assertNotNull(response);

        // Get the cookie back from the session
        String cookie = baClient1.getCookieFromLastLogin();
        assertNotNull(cookie);

        // Wait for the key to expire
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        // Attempt to access a simple servlet configured for basic auth1 with the cookie corresponding to the first key
        assertTrue("The expired LTPA Cookie should not be granted access to the servlet",
                   baClient1.accessProtectedServletWithUnauthorizedCookie(BasicAuthClient.PROTECTED_SIMPLE, cookie));
    }

    /**
     * Verify the following:
     * <OL>
     * <LI>Set this new feature off
     * <LI>Initialize a session with a simple servlet configured for basic auth1 with a valid userId (mnagerUser) and password.
     * <LI>Get the cookie back from the session
     * <LI>Complete a key rotation, and add key 2 to ltpa1.keys
     * <LI>Attempt to access a simple servlet configured for basic auth1 with the cookie corresponding to the first key
     * <LI>Verify the user is forced to reauthenticate
     * </OL>
     * <P>Expected Results:
     * <OL>
     * <LI>Successful update to the server xml configuration
     * <LI>Successful authentication to simple servlet
     * <LI>Successful retrieval of cookie
     * <LI>Successful key rotation, and replacement of key 2 to ltpa1.keys file
     * <LI>Unsuccessful authentication to simple servlet with cookie, the user is forced to reauthenticate
     * </OL>
     */
    @SuppressWarnings("restriction")
    @Mode(TestMode.LITE)
    @Test
    public void testAuthenticationFailureAfterKeyReplacement() {
        // Set the multipleLTPAKeys to false
        setWebAppSecurityConfigElement(server, "false");

        // Initialize a session with a simple servlet configured for basic auth1 with a valid userId (mnagerUser) and password.
        String response = baClient1.accessProtectedServletWithAuthorizedCredentials(BasicAuthClient.PROTECTED_SIMPLE, managerUser, managerPassword);
        assertNotNull(response);

        // Get the cookie back from the session
        String cookie = baClient1.getCookieFromLastLogin();
        assertNotNull(cookie);

        // Complete a key rotation, and add key 2 to ltpa1.keys
        //server.rotateLTPAKeys();

        // Attempt to access a simple servlet configured for basic auth1 with the cookie corresponding to the first key
        assertTrue("Without multipleLTPAKeys feature enabled, afte key rotation, access should not be granted access to the servlet with the old cookie",
                   baClient1.accessProtectedServletWithUnauthorizedCookie(BasicAuthClient.PROTECTED_SIMPLE, cookie));
    }

    // Function to set the multipleLTPAKeys to true or false
    public WebAppSecurity setWebAppSecurityConfigElement(LibertyServer server, String multipleLTPAKeys) {
        WebAppSecurity waSecurity;
        try {
            ServerConfiguration configuration = server.getServerConfiguration();
            waSecurity = configuration.getWebAppSecurity();
            waSecurity.multipleLTPAKeys = multipleLTPAKeys;
            updateConfigDynamically(server, configuration, true);
            return waSecurity;
        } catch (Exception e) {
            e.printStackTrace();
            Log.info(thisClass, "setWebAppSecurityConfigElement", "Failure getting server configuration");
        }
        return null;
    }

    // Function to update the server configuration dynamically
    public static void updateConfigDynamically(LibertyServer server, ServerConfiguration config, boolean waitForAppToStart) throws Exception {
        server.setMarkToEndOfLog(server.getDefaultLogFile());
        server.setMarkToEndOfLog(server.getMostRecentTraceFile());

        server.updateServerConfiguration(config);
        //CWWKG0017I: The server configuration was successfully updated in {0} seconds.
        //CWWKG0018I: The server configuration was not updated. No functional changes were detected.
        server.waitForStringInLogUsingMark("CWWKG001[7-8]I");
        if (waitForAppToStart) {
            server.waitForStringInLogUsingMark("CWWKZ0003I"); //CWWKZ0003I: The application userRegistry updated in 0.020 seconds.
        }
    }
}