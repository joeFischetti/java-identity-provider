/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.common.config.relyingparty.saml;

import edu.internet2.middleware.shibboleth.common.relyingparty.saml2.ArtifactResolutionConfiguration;

/**
 * Spring factory for SAML 2 artifact query profile configurations.
 */
public class SAML2ArtifactResolutionProfileConfigurationFactoryBean extends
        AbstractSAML2ProfileConfigurationFactoryBean {

    /** {@inheritDoc} */
    public Class getObjectType() {
        return ArtifactResolutionConfiguration.class;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        ArtifactResolutionConfiguration configuration = new ArtifactResolutionConfiguration();
        configuration.setAssertionAudiences(getAudiences());
        configuration.setAssertionLifetime(getAssertionLifetime());
        configuration.setDefaultArtifactType(getDefaultArtifactType());
        configuration.setDefaultNameIDFormat(getDefaultNameFormat());
        configuration.setEncryptAssertion(isEncryptAssertions());
        configuration.setEncryptNameID(isEncryptNameIds());
        configuration.setProxyAudiences(getProxyAudiences());
        configuration.setProxyCount(getAssertionProxyCount());
        configuration.setSignAssertions(isSignAssertions());
        configuration.setSigningCredential(getSigningCredential());

        return configuration;
    }
}