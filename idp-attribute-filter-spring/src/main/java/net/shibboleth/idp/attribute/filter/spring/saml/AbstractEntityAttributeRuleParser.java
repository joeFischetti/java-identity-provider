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

package net.shibboleth.idp.attribute.filter.spring.saml;

import net.shibboleth.idp.attribute.filter.spring.policyrule.BasePolicyRuleParser;

import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

// TODO TESTING
/**
 * Base definition for all EntityAttribute Parsers.
 */
public abstract class AbstractEntityAttributeRuleParser extends BasePolicyRuleParser {

    /** {@inheritDoc} */
    protected void doNativeParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {

        builder.addPropertyValue("attributeName", element.getAttributeNS(null, "attributeName"));

        if (element.hasAttributeNS(null, "attributeNameFormat")) {
            builder.addPropertyValue("nameFormat", element.getAttributeNS(null, "attributeNameFormat"));
        }

    }

}