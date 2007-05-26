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

import edu.internet2.middleware.shibboleth.common.relyingparty.provider.saml2.SSOConfiguration;

/**
 * Spring factory for SAML 2 SSO profile configurations.
 */
public class SAML2SSOProfileConfigurationFactoryBean extends AbstractSAML2ProfileConfigurationFactoryBean {

    /** {@inheritDoc} */
    public Class getObjectType() {
        return SSOConfiguration.class;
    }
    
    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        SSOConfiguration configuration = new SSOConfiguration();
        
        populateBean(configuration);
        
        return configuration;
    }
}