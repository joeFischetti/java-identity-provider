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

package net.shibboleth.idp.attribute.filter.policyrule.filtercontext.impl;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.fail;

import java.util.regex.Pattern;

import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.filter.PolicyRequirementRule.Tristate;
import net.shibboleth.idp.attribute.filter.matcher.impl.DataSources;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.UninitializedComponentException;

/**
 * Tests for {@link AttributeRequesterRegexpPolicyRule}.
 */
public class AttributeRequesterRegexpPolicyRuleTest {
    
    private AttributeRequesterRegexpPolicyRule getMatcher() throws ComponentInitializationException {
        AttributeRequesterRegexpPolicyRule matcher = new AttributeRequesterRegexpPolicyRule();
        matcher.setPattern(Pattern.compile("^requ.*"));
        matcher.setId("Test");
        matcher.initialize();
        return matcher;
    }

    @Test public void testAll() throws ComponentInitializationException {

        try {
            new AttributeRequesterRegexpPolicyRule().matches(null);
            fail();
        } catch (UninitializedComponentException ex) {
            // OK
        }
        AttributeRequesterRegexpPolicyRule matcher = getMatcher();
        
        assertEquals(matcher.matches(DataSources.populatedFilterContext(null, null, "wibble")), Tristate.FALSE);
        assertEquals(matcher.matches(DataSources.populatedFilterContext(null, null, "REQUESTER")), Tristate.FALSE);
        assertEquals(matcher.matches(DataSources.populatedFilterContext(null, null, "requester")), Tristate.TRUE);        
    }

    @Test public void testUnpopulated()
            throws ComponentInitializationException {
        assertEquals(getMatcher().matches(DataSources.unPopulatedFilterContext()), Tristate.FALSE);
    }

    @Test public void testNoRequester()
            throws ComponentInitializationException {
        assertEquals(getMatcher().matches(DataSources.populatedFilterContext(null, null, null)), Tristate.FALSE);
    }

}
