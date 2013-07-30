/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.idp.authn.impl;

import java.util.Enumeration;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;

import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationException;
import net.shibboleth.idp.authn.AuthnEventIds;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.idp.authn.context.UsernamePasswordContext;

import org.opensaml.profile.action.ActionSupport;
import org.opensaml.profile.context.ProfileRequestContext;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Charsets;
import com.google.common.net.HttpHeaders;

/**
/**
 * An action that extracts a username and password from the HTTP {@link HttpHeaders#AUTHORIZATION} header,
 * creates a {@link UsernamePasswordContext}, and attaches it to the {@link AuthenticationContext}.
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @event {@link AuthnEventIds#NO_CREDENTIALS}
 * @event {@link AuthnEventIds#INVALID_CREDENTIALS}
 * @pre <pre>ProfileRequestContext.getSubcontext(AuthenticationContext.class, false) != null</pre>
 * @post If ProfileRequestContext.getHttpRequest() != null, the content of the {@link HttpHeaders#AUTHORIZATION}
 * header is parsed and any correctly-encoded information will be attached via a {@link UsernamePasswordContext}.
 */
public class ExtractUsernamePasswordFromBasicAuth extends AbstractAuthenticationAction {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ExtractUsernamePasswordFromBasicAuth.class);
    
    /** {@inheritDoc} */
    protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) throws AuthenticationException {

        final HttpServletRequest request = profileRequestContext.getHttpRequest();
        if (request == null) {
            log.debug("{} profile request context does not contain an HttpServletRequest", getLogPrefix());
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        final String encodedCredentials = extractCredentials(request);
        if (encodedCredentials == null) {
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.NO_CREDENTIALS);
            return;
        }
        
        final Pair<String, String> decodedCredentials = decodeCredentials(encodedCredentials);
        if (decodedCredentials == null) {
            ActionSupport.buildEvent(profileRequestContext, AuthnEventIds.INVALID_CREDENTIALS);
            return;
        }
        
        authenticationContext.getSubcontext(UsernamePasswordContext.class, true)
                .setUsername(decodedCredentials.getFirst()).setPassword(decodedCredentials.getSecond());
    }

    /**
     * Gets the encoded credentials passed in via the {@link HttpHeaders#AUTHORIZATION} header. This method checks to
     * ensure that the authentication scheme is {@link HttpServletRequest#BASIC_AUTH} and then strips off
     * and returns the follow on Base64-encoded credentials.
     * 
     * @param httpRequest current HTTP request
     * 
     * @return the Base64 encoded credentials, or null
     */
    @Nullable protected String extractCredentials(@Nonnull final HttpServletRequest httpRequest) {

        Enumeration<String> header = httpRequest.getHeaders(HttpHeaders.AUTHORIZATION);
        while (header.hasMoreElements()) {
            String[] splitValue = header.nextElement().split(" ");
            if (splitValue.length == 2) {
                String authnScheme = StringSupport.trimOrNull(splitValue[0]);
                if (HttpServletRequest.BASIC_AUTH.equalsIgnoreCase(authnScheme)) {
                    return StringSupport.trimOrNull(splitValue[1]);
                }
            }
        }
        
        log.debug("{} no appropriate Authorization header found", getLogPrefix());
        return null;
    }

    /**
     * Decodes the credential string provided in the HTTP header,
     * splits it in to a username and password, and returns them.
     * 
     * @param encodedCredentials the Base64 encoded credentials
     * 
     * @return a pair containing the username and password, respectively, or null
     */
    @Nullable protected Pair<String, String> decodeCredentials(@Nonnull @NotEmpty final String encodedCredentials) {
        final String decodedUserPass = new String(Base64Support.decode(encodedCredentials), Charsets.US_ASCII);

        if (decodedUserPass != null && decodedUserPass.contains(":")) {
            final String username = decodedUserPass.substring(0, decodedUserPass.indexOf(':'));
            if (username != null && decodedUserPass.length() > username.length() + 1) {
                final String password = decodedUserPass.substring(decodedUserPass.indexOf(':') + 1);
                if (password != null) {
                    return new Pair<String, String>(username, password);
                }
            }
        }

        log.debug("{} request did not contain a well-formed Basic authorization header value");
        return null;
    }
}