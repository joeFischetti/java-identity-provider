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

package net.shibboleth.idp.attribute.resolver.ad.impl;

import javax.annotation.Nonnull;
import javax.annotation.concurrent.ThreadSafe;
import java.util.Collection;
import java.util.ArrayList;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.resolver.AbstractAttributeDefinition;
import net.shibboleth.idp.attribute.resolver.PluginDependencySupport;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolverWorkContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.annotation.constraint.NonnullAfterInit;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.component.ComponentSupport;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.security.DataSealer;
import net.shibboleth.utilities.java.support.security.impl.BasicKeyStrategy;



import org.slf4j.Logger;
import org.slf4j.LoggerFactory;



/**
 * A {@link net.shibboleth.idp.attribute.resolver.AttributeDefinition} that creates an attribute whose values are the
 * values the values of all its dependencies.
 */
@ThreadSafe
public class DecryptedAttributeDefinition extends AbstractAttributeDefinition {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(DecryptedAttributeDefinition.class);

    /** The DataSealer that we'll use to decrypt the attribute **/
    private DataSealer sealer; 


    /**
     * Set the DataSealer (sealer) for this Definition
     * 
     * @param newSealer what to set.
     */
    public void setSealer(@Nonnull @NotEmpty final DataSealer newSealer) {
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        sealer = newSealer;
    }



    /** {@inheritDoc} */
    @Override @Nonnull protected IdPAttribute doAttributeDefinitionResolve(
            @Nonnull final AttributeResolutionContext resolutionContext,
            @Nonnull final AttributeResolverWorkContext workContext) throws ResolutionException {
        Constraint.isNotNull(workContext, "AttributeResolverWorkContext cannot be null");

        final IdPAttribute result = new IdPAttribute(getId());
        result.setValues(PluginDependencySupport.getMergedAttributeValues(workContext,
                getAttributeDependencies(), 
                getDataConnectorDependencies(), 
                getId()));

	Collection<IdPAttributeValue> decryptedAttributes = new ArrayList();

	for(int i = 0; i < result.getValues().size(); i++){
        	log.debug("{} Encrypted Attribute Value: {}", getLogPrefix(), result.getValues().get(i).getDisplayValue());
		
		try{
			String decrypted = sealer.unwrap(result.getValues().get(i).getDisplayValue());

			log.debug("{}: Adding decypted string attribute to collection: {}", getLogPrefix(), decrypted);
			decryptedAttributes.add(new StringAttributeValue(decrypted));
			
		} catch(Exception e){
			log.debug("{}: Error decrypting attribute: {}", getLogPrefix(), e);
		}
		

        }

	final IdPAttribute decryptedResults = new IdPAttribute(getId());
        decryptedResults.setValues(decryptedAttributes);

        return decryptedResults;
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (getDataConnectorDependencies().isEmpty() && getAttributeDependencies().isEmpty()) {
            throw new ComponentInitializationException(getLogPrefix() + " no dependencies were configured");
        }

    }
  
}
