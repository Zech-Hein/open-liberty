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
package io.openliberty.security.oidcclientcore.client;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.ws.webcontainer.security.ProviderAuthenticationResult;

import io.openliberty.security.oidcclientcore.authentication.AbstractFlow;
import io.openliberty.security.oidcclientcore.authentication.Flow;
import io.openliberty.security.oidcclientcore.exceptions.AuthenticationResponseException;
import io.openliberty.security.oidcclientcore.exceptions.TokenRequestException;
import io.openliberty.security.oidcclientcore.token.TokenRefresher;
import io.openliberty.security.oidcclientcore.token.TokenResponse;
import io.openliberty.security.oidcclientcore.token.TokenResponseValidator;
import io.openliberty.security.oidcclientcore.token.TokenValidationException;

public class Client {

    private final OidcClientConfig oidcClientConfig;

    public Client(OidcClientConfig oidcClientConfig) {
        this.oidcClientConfig = oidcClientConfig;
    }

    public ProviderAuthenticationResult startFlow(HttpServletRequest request, HttpServletResponse response) {
        Flow flow = AbstractFlow.getInstance(oidcClientConfig);
        return flow.startFlow(request, response);
    }

    public ProviderAuthenticationResult continueFlow(HttpServletRequest request, HttpServletResponse response) throws AuthenticationResponseException, TokenRequestException {
        Flow flow = AbstractFlow.getInstance(oidcClientConfig);
        return flow.continueFlow(request, response);
    }

    public boolean validate(TokenResponse tokenResponse) throws TokenValidationException {
        TokenResponseValidator tokenResponseValidator = new TokenResponseValidator(this.oidcClientConfig);
        tokenResponseValidator.validate(tokenResponse);
        return false;
    }

    public void processExpiredToken(HttpServletRequest request, HttpServletResponse response) {
        //TODO update
        //OidcTokenImpl(JwtClaims jwtClaims, String access_token, String refresh_token, String client_id, String tokenTypeNoSpace)
        //JwtClaims claims = new JwtClaims(); //TODO Will need OpenIdClaims: openIdCont.getClaims()
        //OidcTokenImpl token = new OidcTokenImpl(claims, openIdCont.getAccessToken().toString(), openIdCont.getRefreshToken().get().getToken(), oidcClientConfig.getClientId(), openIdCont.getTokenType());
        //TokenRefresher tokenRefresher = new TokenRefresher(request, response, oidcClientConfig, token); //TODO update param
        TokenRefresher tokenRefresher = new TokenRefresher(request, response, oidcClientConfig);
        if (tokenRefresher.isTokenExpired()) {

            if (oidcClientConfig.isTokenAutoRefresh()) {

                boolean refreshSucceded = tokenRefresher.refreshToken(); // = true;
                // When the call is not successful, or when there is no previously stored refresh_token field of the Token Response, a logout should be initiated.
                if (!refreshSucceded || tokenRefresher.checkPreviousRefreshValue()) {
                    logout();
                }

            } else {
                LogoutConfig logoutConfig = oidcClientConfig.getLogoutConfig();
                //if ((tokenRefresher.isAccessTokenExpired() && logoutConfig.isAccessTokenExpiry()) ||
                //    (tokenRefresher.isIdTokenExpired() && logoutConfig.isIdentityTokenExpiry())) {
                //    logout();
                // }
                logout();
            }
            // The token expiration is ignored when none of the above conditions hold
        } else {
            System.out.println("ZECH >>> Tokens are not expired but we are refreshing anyways to test...");
            tokenRefresher.refreshToken();
        }
    }

    public void logout() {
        // TODO
    }

}
