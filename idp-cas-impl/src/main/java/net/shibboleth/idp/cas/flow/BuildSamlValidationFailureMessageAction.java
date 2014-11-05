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

package net.shibboleth.idp.cas.flow;

import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml1.core.Response;
import org.opensaml.saml.saml1.core.Status;
import org.opensaml.saml.saml1.core.StatusCode;
import org.opensaml.saml.saml1.core.StatusMessage;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;

/**
 * Creates the SAML response message for failed ticket validation at the <code>/samlValidate</code> URI.
 * The SAML message is bound to the outgoing message context as needed by the
 * {@link org.opensaml.profile.action.impl.EncodeMessage} action.
 *
 * @author Marvin S. Addison
 */
public class BuildSamlValidationFailureMessageAction extends AbstractOutgoingSamlMessageAction {

    @Nonnull
    @Override
    protected Response buildSamlResponse(
            final @Nonnull RequestContext springRequestContext,
            final @Nonnull ProfileRequestContext<SAMLObject, SAMLObject> profileRequestContext) {

        final String code = (String) springRequestContext.getFlashScope().get("code");
        final String detailCode = (String) springRequestContext.getFlashScope().get("detailCode");

        final Response response = newSAMLObject(Response.class, Response.DEFAULT_ELEMENT_NAME);
        final Status status = newSAMLObject(Status.class, Status.DEFAULT_ELEMENT_NAME);
        final StatusCode statusCode = newSAMLObject(StatusCode.class, StatusCode.DEFAULT_ELEMENT_NAME);
        statusCode.setValue(new QName(NAMESPACE, code));
        status.setStatusCode(statusCode);
        final StatusMessage message = newSAMLObject(StatusMessage.class, StatusMessage.DEFAULT_ELEMENT_NAME);
        message.setMessage(detailCode);
        status.setStatusMessage(message);
        response.setStatus(status);

        return response;
    }
}