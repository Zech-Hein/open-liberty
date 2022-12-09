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
package com.ibm.ws.jaxrs.fat.rolesallowed.servlet;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import javax.xml.bind.DatatypeConverter;

import org.junit.Test;

import com.ibm.ws.jaxrs21.fat.security.servlet.SecurityAnnotationsParentTestServlet.BasicAuthFilter;

import componenttest.app.FATServlet;

@WebServlet(urlPatterns = "/RolesAllowedTestServlet")
public class RolesAllowedTestServlet extends FATServlet {

    private static final long serialVersionUID = 4563456788769868446L;

    private Client client;

    @Override
    public void before() throws ServletException {
        //client = ClientBuilder.newClient();
        ClientBuilder cb = ClientBuilder.newBuilder();
        cb.connectTimeout(120000, TimeUnit.MILLISECONDS);
        cb.readTimeout(120000, TimeUnit.MILLISECONDS);
        cb.register(new BasicAuthFilter("user1", "user1pwd"));
        client = cb.build();
    }

    @Override
    public void after() {
        client.close();
    }

    private final String endpoint = "http://localhost:" + Integer.getInteger("bvt.prop.HTTP_default") + "/RolesAllowed/RolesAllowedResource/";

    //@Test
    public void testEveryoneAllowed() throws Exception {
        Response response = null;
        WebTarget t = client.target(endpoint);

        
        response = t.request().get();
        assertEquals(200, response.getStatus());

        client.close();
    }

    @Test
    public void testNotAllowed() throws Exception {
        WebTarget t = client.target(endpoint + "admin");
        CompletableFuture<Response> completableFuture = t.request().accept("text/plain").rx().get().toCompletableFuture();

        try {
            Response response = completableFuture.get();
            assertEquals(200, response.getStatus());
            assertEquals("remotely accessible only to users in **", response.readEntity(String.class));
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        client.close();
    }
    
    public class BasicAuthFilter implements ClientRequestFilter {
      //https://www.ibm.com/support/knowledgecenter/en/SSEQTP_8.5.5/com.ibm.websphere.wlp.doc/ae/cwlp_jaxrs_behavior.html
              private final String usr;
              private final String pwd;

              public BasicAuthFilter(String usr, String pwd) {
                  this.usr = usr;
                  this.pwd = pwd;
              }

              @Override
              public void filter(ClientRequestContext requestContext) throws IOException {
                  MultivaluedMap<String, Object> headers = requestContext.getHeaders();

                  String token = this.usr + ":" + this.pwd;
                  final String basicAuthentication = "Basic " + DatatypeConverter.printBase64Binary(token.getBytes("UTF-8"));
                  headers.add("Authorization", basicAuthentication);
              }
          }
}