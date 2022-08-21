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
import io.openliberty.security.oidcclientcore.token.TokenConstants;

public class Client {

    private final OidcClientConfig oidcClientConfig;

    public Client(OidcClientConfig oidcClientConfig) {
        this.oidcClientConfig = oidcClientConfig;
    }

    public ProviderAuthenticationResult startFlow(HttpServletRequest request, HttpServletResponse response) {
        Flow flow = AbstractFlow.getInstance(oidcClientConfig);
        return flow.startFlow(request, response);
    }

    public ProviderAuthenticationResult continueFlow(HttpServletRequest request, HttpServletResponse response) throws AuthenticationResponseException {
        Flow flow = AbstractFlow.getInstance(oidcClientConfig);
        return flow.continueFlow(request, response);
    }

    public void processExpiredToken(HttpServletRequest request) {

        if (oidcClientConfig.isTokenAutoRefresh()) {
            //try to refresh
            //TODO check only will have one token type below on a request?
            String accessTokenString = request.getParameter(TokenConstants.ACCESS_TOKEN);
            String idTokenString = request.getParameter(TokenConstants.ID_TOKEN);
            String refreshTokenString = request.getParameter(TokenConstants.REFRESH_TOKEN);

            //OpenID Connect provider refreshToken endpoint (token endpoint) has to be called with the following parameters:

            //The ClientId value as taken from OpenIdAuthenticationMechanismDefinition.clientId
            oidcClientConfig.getClientId();

            //The ClientSecret value as taken from OpenIdAuthenticationMechanismDefinition.clientId
            oidcClientConfig.getClientSecret();

            //The grant_type value set to the constant refresh_token

            //the refresh_token value set to the previously stored value from the refresh_token field of the Token Response

            String grantType = TokenConstants.REFRESH_TOKEN;

            //TODO if refresh token is not successful
        } else {
            logout();
        }

    }

    public void logout() {
        // TODO
    }

}
