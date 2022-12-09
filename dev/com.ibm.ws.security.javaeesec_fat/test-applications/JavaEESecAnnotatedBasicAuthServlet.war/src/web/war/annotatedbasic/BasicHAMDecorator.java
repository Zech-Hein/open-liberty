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

import javax.annotation.Priority;
import javax.decorator.Decorator;
import javax.decorator.Delegate;
import javax.inject.Inject;
import javax.security.enterprise.AuthenticationException;
import javax.security.enterprise.AuthenticationStatus;
import javax.security.enterprise.authentication.mechanism.http.HttpAuthenticationMechanism;
import javax.security.enterprise.authentication.mechanism.http.HttpMessageContext;
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
@Decorator
@Priority(100)
public class BasicHAMDecorator implements HttpAuthenticationMechanism {
    @SuppressWarnings("unused")
    private static Logger log = Logger.getLogger(BasicHAMDecorator.class.getName());

    @Inject
    @Delegate
    private HttpAuthenticationMechanism delegateHAM;

    @Override
    public AuthenticationStatus validateRequest(HttpServletRequest request, HttpServletResponse response, HttpMessageContext httpMessageContext) throws AuthenticationException {
        HttpMessageContext httpContextWrapper = new BasicHAMMessageContextWrapper(response, httpMessageContext);
        response.addHeader("BasicHAMDecorator", "I have been decorated!");
        return delegateHAM.validateRequest(request, response, httpContextWrapper);
    }

}
