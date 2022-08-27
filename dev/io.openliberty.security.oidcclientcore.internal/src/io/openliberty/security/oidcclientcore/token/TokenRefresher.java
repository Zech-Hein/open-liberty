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

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
//import com.ibm.websphere.security.openidconnect.token.IdToken; //TODO remove if not needed
//import com.ibm.ws.security.openidconnect.client.jose4j.OidcTokenImpl;

import io.openliberty.security.oidcclientcore.client.OidcClientConfig;
import io.openliberty.security.oidcclientcore.client.OidcProviderMetadata;
import io.openliberty.security.oidcclientcore.token.TokenRequestor.Builder;

public class TokenRefresher {

    private static final TraceComponent tc = Tr.register(TokenRefresher.class);

    private HttpServletRequest request = null;
    private HttpServletResponse response = null;
    private OidcClientConfig oidcClientConfig = null;
    //private final OpenIdContext openIdContext = null; //TODO remove if not needed

    private final String accessToken = null;
    private OidcTokenImpl oidcTokenImpl = null;
    private final String refreshToken = null;

    private boolean accessTokenExpired = false;
    private final boolean identityTokenExpired = false;

    //TODO remove if not needed
    //For compile sake
    public TokenRefresher() {
        this(null, null, null, null);
    }

    public TokenRefresher(HttpServletRequest req, HttpServletResponse resp, OidcClientConfig clientConfig, OidcTokenImpl oidcToken) {
        request = req;
        response = resp;
        oidcClientConfig = clientConfig;
        //openIdContext = openIdCont;
        oidcTokenImpl = oidcToken;

        //openIdContext.getExpiresIn(); // AccessToken expires_in
        //openIdContext.getIdentityToken().isExpired(); or call method like OidcClientCache.isIdTokenValid(IdToken idToken, long cushionMilliseconds);
        //use existing IdToken class
        //idToken = //TODO openIdContext.getIdentityToken() IdentityToken != IdToken interfaces

        //TODO - Confirm how TokenRefresher should get the tokens for each request?
        //accessToken = request.getParameter(TokenConstants.ACCESS_TOKEN);
        //idToken = request.getParameter(TokenConstants.ID_TOKEN);
        //refreshToken = request.getParameter(TokenConstants.REFRESH_TOKEN);

        //TODO do more searching on oidc token exp parsing
        //TODO set

    }

    public boolean isTokenExpired() {
        if (accessToken != null) {
            accessTokenExpired = checkTokenExpiration(accessToken);
        }
        //if (idToken != null) {
        //    identityTokenExpired = checkTokenExpiration(idToken);
        // }

        return accessTokenExpired || identityTokenExpired;
    }

    private boolean checkTokenExpiration(String tokenString) {

        return false;
    }

    private boolean isIdTokenValid(long cushionMilliseconds) {
        long expSeconds = oidcTokenImpl.getExpirationTimeSeconds(); //IdToken.getExpirationTimeSeconds();
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

    public boolean isAccessTokenExpired() {
        return accessTokenExpired;
    }

    public boolean isIdentityTokenExpired() {
        return identityTokenExpired;
    }

    public boolean checkPreviousRefreshValue() {
        return false;
    }

    public boolean refreshToken(OidcProviderMetadata oidcProviderMetadata) {
        //TODO
        // In the case a refresh of the token is needed,
        // the OpenID Connect provider refreshToken endpoint (token endpoint) has to be called with the following parameters

        //The ClientId value as taken from OpenIdAuthenticationMechanismDefinition.clientId
        //oidcClientConfig.getClientId();
        //The ClientSecret value as taken from OpenIdAuthenticationMechanismDefinition.clientId
        //oidcClientConfig.getClientSecret();
        //The grant_type value set to the constant refresh_token
        //String grantType = TokenConstants.REFRESH_TOKEN;

        //TODO remove hardcodes
        String tokenEndpoint = "";
        String redirectUrl = "";
        String authzCode = "";

        //Builder tokenRequestBuilder = new TokenRequestor.Builder(oidcProviderMetadata.getTokenEndpoint(), oidcClientConfig.getClientId(), oidcClientConfig.getClientSecret(), redirectUrl, authzCode);
        Builder tokenRequestBuilder = new TokenRequestor.Builder(tokenEndpoint, oidcClientConfig.getClientId(), oidcClientConfig.getClientSecret().toString(), redirectUrl, authzCode);
        //tokenRequestBuilder.sslSocketFactory(sslSocketFactory);
        tokenRequestBuilder.grantType(TokenConstants.REFRESH_TOKEN);
        //tokenRequestBuilder.isHostnameVerification(oidcClientConfig.isHostNameVerificationEnabled());
        //tokenRequestBuilder.authMethod(oidcClientConfig.getTokenEndpointAuthMethod());
        //tokenRequestBuilder.resources(OIDCClientAuthenticatorUtil.getResources(clientConfig));
        //tokenRequestBuilder.customParams(clientConfig.getTokenRequestParams());
        //tokenRequestBuilder.useSystemPropertiesForHttpClientConnections(oidcClientConfig.getUseSystemPropertiesForHttpClientConnections());
        TokenRequestor tokenRequestor = tokenRequestBuilder.build();

        TokenResponse tokenResponse = null;//tokenRequestor.requestTokens();
        Map<String, String> tokens = tokenResponse.asMap();

        //oidcClientRequest.setTokenType(ClientConstants.TYPE_ID_TOKEN);

        // this has a LOT of dependencies.
        //ProviderAuthenticationResult oidcResult = jose4jUtil.createResultWithJose4J(responseState, tokens, clientConfig, oidcClientRequest);

        //the refresh_token value set to the previously stored value from the refresh_token field of the Token Response
        // 3 posibilities: 1. Subject, 2. Session, 3. Cookie

        //When the call is successful and a new Access Token is received, the same logic is applied as described above;
        //Validate tokens
        //Store in context
        //Determine the caller Name and Caller groups values (which can lead to more or less permissions in the application)

        //TODO
        return false;
    }

}
