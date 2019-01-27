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

package net.shibboleth.idp.attribute.resolver.spring.dc.impl;

import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.xml.namespace.QName;

import net.shibboleth.idp.attribute.resolver.spring.BaseResolverPluginParser;
import net.shibboleth.idp.attribute.resolver.spring.dc.AbstractDataConnectorParser;
import net.shibboleth.idp.attribute.resolver.spring.impl.AttributeResolverNamespaceHandler;
import net.shibboleth.idp.attribute.resolver.spring.impl.InputAttributeDefinitionParser;
import net.shibboleth.idp.attribute.resolver.spring.impl.InputDataConnectorParser;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport;
import net.shibboleth.utilities.java.support.primitive.StringSupport;
import net.shibboleth.utilities.java.support.primitive.DeprecationSupport.ObjectType;
import net.shibboleth.utilities.java.support.xml.AttributeSupport;
import net.shibboleth.utilities.java.support.xml.DOMTypeSupport;
import net.shibboleth.utilities.java.support.xml.ElementSupport;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

/**
 * Spring bean definition parser for configuring
 * {@link net.shibboleth.idp.saml.attribute.resolver.impl.ComputedIDDataConnector} and
 * {@link net.shibboleth.idp.saml.attribute.resolver.impl.StoredIDDataConnector}.
 */
public abstract class BaseComputedIDDataConnectorParser extends BaseResolverPluginParser {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(BaseComputedIDDataConnectorParser.class);

    /**
     * Parse the common definitions for {@link net.shibboleth.idp.saml.attribute.resolver.impl.ComputedIDDataConnector}
     * and {@link net.shibboleth.idp.saml.attribute.resolver.impl.StoredIDDataConnector}.
     * 
     * @param config the DOM element under consideration.
     * @param parserContext Spring's context.
     * @param builder Spring's bean builder.
     * @param generatedIdDefaultName the name to give the generated Attribute if none was provided.
     */
    // Checkstyle: CyclomaticComplexity|MethodLength OFF
    protected void doParse(@Nonnull final Element config, @Nonnull final ParserContext parserContext,
            @Nonnull final BeanDefinitionBuilder builder, @Nullable final String generatedIdDefaultName) {
        super.doParse(config, parserContext, builder);
        
        final QName suppliedQname = DOMTypeSupport.getXSIType(config);
        if (!AttributeResolverNamespaceHandler.NAMESPACE.equals(suppliedQname.getNamespaceURI())) {
            DeprecationSupport.warnOnce(ObjectType.XSITYPE, suppliedQname.toString(),
                    parserContext.getReaderContext().getResource().getDescription(), getPreferredName().toString());
        } 
        
        final String generatedAttribute;
        if (config.hasAttributeNS(null, "generatedAttributeID")) {
            generatedAttribute = StringSupport.trimOrNull(config.getAttributeNS(null, "generatedAttributeID"));
        } else {
            generatedAttribute = generatedIdDefaultName;
        }

        final List<Element> failoverConnector = ElementSupport.getChildElements(config, 
                AbstractDataConnectorParser.FAILOVER_DATA_CONNECTOR_ELEMENT_NAME);
        if (failoverConnector != null && !failoverConnector.isEmpty()) {
            if (failoverConnector.size() > 1) {
                log.warn("{} More than one failover data connector specified, taking the first",
                        getLogPrefix());                
            }
            
            final String connectorId = StringSupport.trimOrNull(failoverConnector.get(0).getAttributeNS(null, "ref"));
            log.debug("{} Setting the following failover data connector dependencies: {}", getLogPrefix(), connectorId);
            builder.addPropertyValue("failoverDataConnectorId", connectorId);
        }

        if (config.hasAttributeNS(null, "algorithm")) {
            builder.addPropertyValue("algorithm", config.getAttributeNS(null, "algorithm"));
        }

        if (config.hasAttributeNS(null, "encoding")) {
            builder.addPropertyValue("encoding", config.getAttributeNS(null, "encoding"));
        }

        final String salt;
        if (AttributeSupport.hasAttribute(config, new QName("salt"))) {
            salt = config.getAttributeNS(null, "salt");
        } else {
            salt = null;
        }
        
        if (null == salt) {
            log.debug("{} Generated Attribute: '{}', no salt provided", getLogPrefix(), generatedAttribute);
        } else {
            log.debug("{} Generated Attribute: '{}', see TRACE log for the salt value", 
                    getLogPrefix(), generatedAttribute);
            log.trace("{} salt: '{}'", getLogPrefix(), salt);
        }

        builder.addPropertyValue("generatedAttributeId", generatedAttribute);
        builder.addPropertyValue("salt", salt);
    }
    // Checkstyle: CyclomaticComplexity|MethodLength ON

    /**
     * return a string which is to be prepended to all log messages.
     * 
     * @return "Attribute Definition: '<definitionID>' :"
     */
    @Override
    @Nonnull @NotEmpty protected String getLogPrefix() {
        final StringBuilder builder = new StringBuilder("Data Connector '").append(getDefinitionId()).append("':");
        return builder.toString();
    }
    
    /**
     * Helper function to assist rewrite from old to new QName.
     * 
     * @return the "new" type
     */
    protected abstract QName getPreferredName();
    
}