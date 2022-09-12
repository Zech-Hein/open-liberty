/*******************************************************************************
 * Copyright (c) 2022 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package io.openliberty.security.oidcclientcore.token;

import java.util.Date;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;

import com.ibm.websphere.ras.ProtectedString;
import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;

import io.openliberty.security.oidcclientcore.client.OidcClientConfig;
import io.openliberty.security.oidcclientcore.exceptions.TokenRequestException;
import io.openliberty.security.oidcclientcore.token.TokenRequestor.Builder;

public class TokenRefresher {

    private static final TraceComponent tc = Tr.register(TokenRefresher.class);

    public static final String CREDENTIAL_STORING_TIME_MILLISECONDS = "com.ibm.wssi.security.oidc.client.credential.storing.utc.time.milliseconds"; // GMT==UTC

    private HttpServletRequest request = null;
    private HttpServletResponse response = null;
    private OidcClientConfig oidcClientConfig = null;
    //private final OpenIdContext openIdContext = null; //TODO remove if not needed

    //private final String accessToken = null;
    private OidcTokenImpl oidcTokenImpl = null;
    //private String refreshToken = null;

    private Boolean accessTokenExpired = null;
    private Boolean idTokenExpired = null;

    //TODO remove harcoded values
    private static String accessToken = "qOuZdH6Anmxclul5d71AXoDbFVmRG2dPnHn9moaw";
    private static final String tokenType = "bearer";
    private static final Long expiresIn = 3599L;
    private static final String scope = "openid profile";
    private static String refreshToken = "QGCYpfziPZY2saAagbsf5jxbMucqcF3743euknBxzkUlof7uSv";
    private static String idToken = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vaGFybW9uaWM6ODAxMS9vYXV0aDIvZW5kcG9pbnQvT0F1dGhDb25maWdTYW1wbGUvdG9rZW4iLCJpYXQiOjEzODczODM5NTMsInN1YiI6InRlc3R1c2VyIiwiZXhwIjoxMzg3Mzg3NTUzLCJhdWQiOiJjbGllbnQwMSJ9.ottD3eYa6qrnItRpL_Q9UaKumAyo14LnlvwnyF3Kojk";

    //TODO remove
    //For compile sake
    public TokenRefresher() {
        this(null, null, null, null);
    }

    public TokenRefresher(HttpServletRequest req, HttpServletResponse resp, OidcClientConfig clientConfig) {
        this(req, resp, clientConfig, null);
    }

    public TokenRefresher(HttpServletRequest req, HttpServletResponse resp, OidcClientConfig clientConfig, OidcTokenImpl oidcToken) {
        request = req;
        response = resp;
        oidcClientConfig = clientConfig;
        //openIdContext = openIdCont;
        oidcTokenImpl = oidcToken;

        //TODO uncomment refreshToken = oidcTokenImpl.getRefreshToken();

        //openIdContext.getExpiresIn(); // AccessToken expires_in
        //openIdContext.getIdentityToken().isExpired(); or call method like OidcClientCache.isIdTokenValid(IdToken idToken, long cushionMilliseconds);
        //use existing IdToken(oidcTokenImpl) class
        //idToken = //TODO openIdContext.getIdentityToken() IdentityToken != IdToken interfaces
        String sysIdToken = System.getProperty(TokenConstants.ID_TOKEN);
        System.out.println("ZECH >>>> system IdToken: " + sysIdToken);
        String sysAccessToken = System.getProperty(TokenConstants.ACCESS_TOKEN);
        System.out.println("ZECH >>>> system AccessToken: " + sysAccessToken);
        String sysRefreshToken = System.getProperty(TokenConstants.REFRESH_TOKEN);
        System.out.println("ZECH >>>> system RefreshToken: " + sysRefreshToken);

        if (sysIdToken != null)
            idToken = sysIdToken;
        if (sysAccessToken != null)
            accessToken = sysAccessToken;
        if (sysRefreshToken != null)
            refreshToken = sysRefreshToken;
    }

    public boolean isTokenExpired() {
        return isAccessTokenExpired() || isIdTokenExpired();
    }

    public boolean isAccessTokenExpired() {
        if (accessTokenExpired == null)
            accessTokenExpired = !isAccessTokenValid(0);

        return accessTokenExpired;
    }

    public boolean isIdTokenExpired() {
        if (idTokenExpired == null)
            idTokenExpired = !isIdTokenValid(0);

        return idTokenExpired;
    }

    //TODO: remove cushionMilliseconds? was used in OidcClientCache.java
    private boolean isAccessTokenValid(long cushionMilliseconds) {

        /*
         * Subject subject = //TODO
         * String strExpiresIn = (String) getOAuthAttribute(subject, "expires_in");
         * if (strExpiresIn == null || strExpiresIn.isEmpty()) {
         * // In this case, the access_token was not produced by the RP
         * // It must be an access_token came in through RS.
         * // But in RS, no custom cookie is produced (no matter the inboundPropagation is required or supported)
         * // So, it should never be here. But return false in case something strange happened
         * return false;
         * }
         */
        //long lExpiresIn = 0l;
        //TODO refactor later
        //long lExpiresIn = oidcTokenImpl.expiresIn;
        long lExpiresIn = expiresIn; //TODO remove hardcode
        try {

            //lExpiresIn = Long.parseLong(strExpiresIn) * 1000; //cushionMilliseconds change from seconds to milliseconds
        } catch (NumberFormatException e) {
            // This should not happen
            // if it happens, the ExpiresIn will be 0L
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "hit unexpected exception", e);
            }
        }
        //TODO refactor later
        //TODO remove hardcode oidcTokenImpl.getIssuedAtTimeSeconds();
        long iat = 1516239022; //Expired January
        Long storeTimeMilliseconds = iat * 1000; //(Long) getOAuthAttribute(subject, CREDENTIAL_STORING_TIME_MILLISECONDS);

        Date date = new Date();
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "date(" + date.getTime() + ") storeMilli(" + storeTimeMilliseconds + ") cushion(" + cushionMilliseconds + ")");
        }
        if (storeTimeMilliseconds + lExpiresIn - cushionMilliseconds > date.getTime()) {
            return true;
        }

        return false;
    }

    //TODO: remove cushionMilliseconds? was used in OidcClientCache.java
    private boolean isIdTokenValid(long cushionMilliseconds) {
        long expSeconds = 0;

        try {
            expSeconds = getIdTokenExpiration(idToken);
        } catch (Exception e) {
            Tr.debug(tc, "isIdTokenValid EXCEPTION: \n" + e.toString());
        }
        //TODO remove harcode //oidcTokenImpl.getExpirationTimeSeconds(); //IdToken.getExpirationTimeSeconds();
        //long atIssue = idToken.getIssuedAtTimeSeconds();
        Date date = new Date();
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "date(" + date.getTime() + ") expSec(" + expSeconds + ") cushionMillisec(" + cushionMilliseconds + ")");
        }
        if (expSeconds * 1000 - cushionMilliseconds > date.getTime()) { // We want it expires earlier with cushion
            return true;
        }
        return false;
    }

    //TODO remove (for temporary use)
    private long getIdTokenExpiration(String idToken) throws Exception {
        JwtContext jwtcontext = null;
        try {
            jwtcontext = parseJwtWithoutValidation(idToken);

        } catch (Exception e) {
            String error = e.getMessage() != null ? e.getMessage() : "not a valid id token";
            throw new Exception(this.oidcClientConfig.getClientId() + error);
        }

        JwtClaims jwtClaims = null;
        if (jwtcontext != null && jwtcontext.getJwtClaims() != null) {
            jwtClaims = jwtcontext.getJwtClaims();
            // must have claims - iat and exp
        }
        return jwtClaims.getExpirationTime().getValue();
    }

    //Just parse without validation for now
    //TODO remove (for temporary use)
    public static JwtContext parseJwtWithoutValidation(String jwtString) throws Exception {
        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder().setSkipAllValidators().setDisableRequireSignature().setSkipSignatureVerification().build();

        return firstPassJwtConsumer.process(jwtString);
    }

    public boolean checkPreviousRefreshValue() {
        return false;
    }

    public boolean refreshToken() {
        JakartaOidcTokenRequest tokenRequest = new JakartaOidcTokenRequest(oidcClientConfig, request);
        try {
            tokenRequest.sendTokenRefreshRequest(refreshToken);
        } catch (TokenRequestException e) {
            // TODO Auto-generated catch block
            // Do you need FFDC here? Remember FFDC instrumentation and @FFDCIgnore
            e.printStackTrace();
        }
        return true;
    }

    //TODO: remove
    public boolean oldRefreshToken() {

        // In the case a refresh of the token is needed,
        // the OpenID Connect provider refreshToken endpoint (token endpoint) has to be called with the following parameters

        //The ClientId value as taken from OpenIdAuthenticationMechanismDefinition.clientId
        // oidcClientConfig.getClientId();
        //The ClientSecret value as taken from OpenIdAuthenticationMechanismDefinition.clientId
        // oidcClientConfig.getClientSecret();
        //The grant_type value set to the constant refresh_token
        // String grantType = TokenConstants.REFRESH_TOKEN;

        //TODO remove hardcodes
        String tokenEndpoint = oidcClientConfig.getProviderMetadata().getTokenEndpoint();
        String redirectUrl = "";
        String authzCode = "";

        String clientSecret = null;
        ProtectedString clientSecretProtectedString = oidcClientConfig.getClientSecret();
        if (clientSecretProtectedString != null) {
            clientSecret = new String(clientSecretProtectedString.getChars());
        }

        //Builder tokenRequestBuilder = new TokenRequestor.Builder(oidcProviderMetadata.getTokenEndpoint(), oidcClientConfig.getClientId(), oidcClientConfig.getClientSecret(), redirectUrl, authzCode);
        Builder tokenRequestBuilder = new TokenRequestor.Builder(tokenEndpoint, oidcClientConfig.getClientId(), clientSecret, redirectUrl, authzCode);
        //tokenRequestBuilder.sslSocketFactory(sslSocketFactory);
        tokenRequestBuilder.grantType(TokenConstants.REFRESH_TOKEN);
        //tokenRequestBuilder.isHostnameVerification(oidcClientConfig.isHostNameVerificationEnabled());
        //tokenRequestBuilder.authMethod(oidcClientConfig.getTokenEndpointAuthMethod());
        //tokenRequestBuilder.resources(OIDCClientAuthenticatorUtil.getResources(clientConfig));
        //tokenRequestBuilder.customParams(clientConfig.getTokenRequestParams());
        //tokenRequestBuilder.useSystemPropertiesForHttpClientConnections(oidcClientConfig.getUseSystemPropertiesForHttpClientConnections());
        TokenRequestor tokenRequestor = tokenRequestBuilder.build();

        TokenResponse tokenResponse = null;
        Map<String, String> tokens = null;

        try {
            tokenResponse = tokenRequestor.requestTokens();
            tokens = tokenResponse.asMap();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            // Do you need FFDC here? Remember FFDC instrumentation and @FFDCIgnore
            e.printStackTrace();
        }

        //oidcClientRequest.setTokenType(ClientConstants.TYPE_ID_TOKEN);

        // this has a LOT of dependencies.
        //ProviderAuthenticationResult oidcResult = jose4jUtil.createResultWithJose4J(responseState, tokens, clientConfig, oidcClientRequest);

        //the refresh_token value set to the previously stored value from the refresh_token field of the Token Response

        //When the call is successful and a new Access Token is received, the same logic is applied as described above;
        //Validate tokens
        //Store in context
        //Determine the caller Name and Caller groups values (which can lead to more or less permissions in the application)

        //TODO
        return false;
    }

}
