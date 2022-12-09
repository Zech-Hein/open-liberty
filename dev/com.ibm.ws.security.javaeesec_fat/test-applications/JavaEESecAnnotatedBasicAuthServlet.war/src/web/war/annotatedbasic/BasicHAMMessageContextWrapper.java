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
package web.war.annotatedbasic;

import java.util.logging.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Default;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContextWrapper;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/*
 * This class is an HttpAuthenticationMechanism(HAM) but because it is annotated as a @Decorator it is used to decorate or enhance another HAM.
 * In this application the servlet is annotated with @BasicAuthenticationMechanismDefinition(realmName = "JavaEESec Basic Realm").
 * So Liberty's built-in BasicAuthenticationMechanism HAM will be used as the HAM for the app. It will be injected as the delegateHAM in this decorator.
 *
 * Using this decorator HAM allows for the HAM behavior to be modified for this application without having to modify the original HAM.
 *
 * In this case, the HAM behavior is modified (decorated) by adding a "BasicHAMDecorator" header to the response with a value "I have been decorated!"
 *
 */
@Default
@ApplicationScoped
public class BasicHAMMessageContextWrapper extends HttpMessageContextWrapper {
    @SuppressWarnings("unused")
    private static Logger log = Logger.getLogger(BasicHAMMessageContextWrapper.class.getName());

    private final HttpServletResponse response;

    public BasicHAMMessageContextWrapper(HttpServletResponse response, HttpMessageContext httpMessageContext) {
        super(httpMessageContext);
        this.response = response;
        HttpServletRequest request = httpMessageContext.getRequest();
        System.out.println("ZECH >>> Printing request: " + request);
        System.out.println("ZECH >>> getAuthType" + request.getAuthType());
        System.out.println("ZECH >>> getAuthType" + request.getRemoteUser());

    }

    @Override
    public AuthenticationStatus responseUnauthorized() {
        response.addHeader("BasicHAMMessageContextWrapper", "I have been wrapped!");
        return super.responseUnauthorized();
    }

}
