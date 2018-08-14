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

package net.shibboleth.idp.authn.duo.impl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Map;

import javax.annotation.Nonnull;

import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.utils.URIBuilder;

import com.duosecurity.duoweb.DuoWebException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.google.common.escape.Escaper;
import com.google.common.net.UrlEscapers;

import net.shibboleth.idp.authn.duo.DuoAuthAPI;
import net.shibboleth.idp.authn.duo.DuoIntegration;
import net.shibboleth.idp.authn.duo.context.DuoAuthenticationContext;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/**
 * Implementation of the the Duo AuthApi /v2/auth endpoint.
 */
public class DuoAuthAuthenticator extends AbstractDuoAuthenticator {
    
    /** pushinfo escaper. */
    @Nonnull private final Escaper paramEscaper;

    /** a TypeReference for the repsonse generated by the endpoint. */
    @Nonnull private final TypeReference<DuoResponseWrapper<DuoAuthResponse>> wrapperTypeRef;
    
    /** Constructor. */
    public DuoAuthAuthenticator() {
        wrapperTypeRef = new TypeReference<DuoResponseWrapper<DuoAuthResponse>>() {};
        paramEscaper = UrlEscapers.urlFormParameterEscaper();
    }
    
    /**
     * Perform an authentication action via the Duo AuthApi /auth endpoint.
     * 
     * @param duoContext Duo authentication context to use
     * @param duoIntegration Duo integration to use
     * 
     * @return a {@link DuoAuthResponse}
     * 
     * @throws DuoWebException if an error occurs
     */
    public DuoAuthResponse authenticate(@Nonnull final DuoAuthenticationContext duoContext,
            @Nonnull final DuoIntegration duoIntegration) throws DuoWebException {

        try {
            // prepare the request
            final URI uri = new URIBuilder().setScheme("https").setHost(duoIntegration.getAPIHost())
                    .setPath("/auth/v2/auth").build();
            final RequestBuilder rb =
                    RequestBuilder.post().setUri(uri).addParameter(DuoAuthAPI.DUO_USERNAME, duoContext.getUsername());
            if (duoContext.getClientAddress() != null) {
                rb.addParameter(DuoAuthAPI.DUO_IPADDR, duoContext.getClientAddress());
            }
            if (duoContext.getFactor() != null) {
                rb.addParameter(DuoAuthAPI.DUO_FACTOR, duoContext.getFactor());
            }
            if (duoContext.getDeviceID() != null) {
                rb.addParameter(DuoAuthAPI.DUO_DEVICE, duoContext.getDeviceID());
            }
            if (duoContext.getPasscode() != null) {
                rb.addParameter(DuoAuthAPI.DUO_PASSCODE, duoContext.getPasscode());
            }
            if (!duoContext.getPushInfo().isEmpty()) {
                final ArrayList<String> pushinfo = new ArrayList<String>(duoContext.getPushInfo().size());
                for (final Map.Entry<String,String> entry : duoContext.getPushInfo().entrySet()) {
                    pushinfo.add(paramEscaper.escape(entry.getKey()) + "=" + paramEscaper.escape(entry.getValue()));
                }
                rb.addParameter(DuoAuthAPI.DUO_PUSHINFO, StringSupport.listToStringValue(pushinfo, "&"));
            }
            DuoSupport.signRequest(rb, duoIntegration);
            final HttpUriRequest request = rb.build();

            // do it
            return doAPIRequest(request, wrapperTypeRef).getResponse();
        } catch (final IOException | URISyntaxException | InvalidKeyException | NoSuchAlgorithmException ex) {
            throw new DuoWebException("Duo AuthAPI auth request failed: " + ex.getMessage());
        }
    }

}