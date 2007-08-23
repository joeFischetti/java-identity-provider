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

package edu.internet2.middleware.shibboleth.common.config.attribute.resolver.attributeDefinition;

import org.opensaml.util.storage.StorageService;

import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.TransientIdAttributeDefinition;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition.TransientIdAttributeDefinition.IdEntry;

/**
 * Spring factory bean producing {@link TransientIdAttributeDefinition}s.
 */
public class TransientIdAttribtueDefinitionFactoryBean extends BaseAttributeDefinitionFactoryBean {

    /** Store used to map transient identifier tokens to principal names. */
    private StorageService<String, IdEntry> identifierStore;

    /** {@inheritDoc} */
    public Class getObjectType() {
        return TransientIdAttributeDefinition.class;
    }

    /**
     * Gets the store used to map transient identifier tokens to principal names.
     * 
     * @return store used to map transient identifier tokens to principal names
     */
    public StorageService<String, IdEntry> getIdentifierStore() {
        return identifierStore;
    }

    /**
     * Sets the store used to map transient identifier tokens to principal names.
     * 
     * @param store store used to map transient identifier tokens to principal names
     */
    public void setIdentifierStore(StorageService<String, IdEntry> store) {
        identifierStore = store;
    }

    /** {@inheritDoc} */
    protected Object createInstance() throws Exception {
        TransientIdAttributeDefinition definition = new TransientIdAttributeDefinition(getIdentifierStore());
        populateAttributeDefinition(definition);

        return definition;
    }
}
