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

package net.shibboleth.idp.attribute.filter.spring.basic;

import java.util.Map;
import java.util.Set;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.AttributeValue;
import net.shibboleth.idp.attribute.filter.AttributeFilterContext;
import net.shibboleth.idp.attribute.filter.PolicyRequirementRule.Tristate;
import net.shibboleth.idp.attribute.filter.impl.matcher.ScriptedMatcher;
import net.shibboleth.idp.attribute.filter.impl.policyrule.ScriptedPolicyRule;
import net.shibboleth.idp.attribute.filter.spring.BaseAttributeFilterParserTest;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/** test for parsing scripted matchers and scripted parsers.
 *
 */
public class ScriptedTest extends BaseAttributeFilterParserTest {

    private Map<String, IdPAttribute> epaUid;

    @BeforeClass public void setupAttributes() throws ComponentInitializationException, ResolutionException {

        epaUid = getAttributes("epa-uidwithjsmith.xml");
    }

    @Test public void policy() throws ComponentInitializationException {
        final ScriptedPolicyRule rule = (ScriptedPolicyRule) getPolicyRule("scripted.xml");

        AttributeFilterContext filterContext = new AttributeFilterContext();
        filterContext.setPrefilteredAttributes(epaUid.values());
        Assert.assertEquals(rule.matches(filterContext), Tristate.FALSE);
    }
    
    @Test(expectedExceptions={BeanDefinitionStoreException.class,}) public void policyNotFound() throws ComponentInitializationException {
        getPolicyRule("scriptedNotThere.xml");
    }
    
    @Test public void matcher()  throws ComponentInitializationException {
        final ScriptedMatcher matcher = (ScriptedMatcher) getMatcher("scripted.xml");
        
        AttributeFilterContext filterContext = new AttributeFilterContext();
        filterContext.setPrefilteredAttributes(epaUid.values());
        Set<AttributeValue> x = matcher.getMatchingValues(epaUid.get("uid"), filterContext);
        Assert.assertEquals(x.size(), 1);
        String val = (String) x.iterator().next().getValue();
        Assert.assertTrue(val.equals("jsmith") || val.equals("daffyDuck"));
        
    }

}
