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

import net.shibboleth.idp.attribute.IdPAttribute;
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

    /** key value. */
    @NonnullAfterInit private String key;

    private BasicKeyStrategy strategy;

    private DataSealer sealer; 


    /**
     * Set the key for this definition.
     * 
     * @param newKey what to set.
     */
    public void setKey(@Nonnull @NotEmpty final String newKey) {
        ComponentSupport.ifDestroyedThrowDestroyedComponentException(this);
        ComponentSupport.ifInitializedThrowUnmodifiabledComponentException(this);

        key = Constraint.isNotNull(StringSupport.trimOrNull(newKey), "Key can not be null or empty");


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

	for(int i = 0; i < result.getValues().size(); i++){
        	log.debug("{} Encrypted Attribute Value: {}", getLogPrefix(), result.getValues().get(i).getDisplayValue());
		
		try{
			log.trace("{} Encryption key: {}", getLogPrefix(), strategy.getKey("key").getEncoded());
			String decrypted = sealer.unwrap(result.getValues().get(i).getDisplayValue());

			log.debug("{}: Attempted decryption using DataSealer key provided: {}", getLogPrefix(), decrypted);
		} catch(Exception e){
			log.debug("{}: Error decrypting attribute: {}", getLogPrefix(), e);
		}
		

        }

	

        return result;
    }

    /** {@inheritDoc} */
    @Override protected void doInitialize() throws ComponentInitializationException {
        super.doInitialize();

        if (getDataConnectorDependencies().isEmpty() && getAttributeDependencies().isEmpty()) {
            throw new ComponentInitializationException(getLogPrefix() + " no dependencies were configured");
        }
        strategy = new BasicKeyStrategy();
        strategy.setSecretKey(key);

        sealer = new DataSealer();
        sealer.setKeyStrategy(strategy);

	try{
	    strategy.initialize();
            sealer.initialize();
	    log.debug("{} Initialized DataSealer and Key Strategy for attribute decryption", getLogPrefix());
        } catch (Exception e) {
            log.debug("{} Couldn't initialize DataSealer or Key Strategy: {}", getLogPrefix(), e);
        }



    }
  
}
