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

package net.shibboleth.idp.attribute.resolver.impl.ad;

import javax.annotation.Nullable;

import junit.framework.Assert;
import net.shibboleth.idp.attribute.Attribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;

import org.testng.annotations.Test;

import com.google.common.base.Function;
import com.google.common.base.Optional;

/**
 * Test for {@link PrincipalAuthenticationMethodAttributeDefinition}
 */
public class PrincipalAuthenticationMethodAttributeDefinitionTest {
    
    @Test
    public void testNullStrategy() {
        PrincipalAuthenticationMethodAttributeDefinition defn = new PrincipalAuthenticationMethodAttributeDefinition();
        defn.setId("id");
        
        try {
            defn.initialize();
            Assert.fail();
        } catch (ComponentInitializationException e) {
            // ok
        }
    }

    @Test
    public void testEmptyMethod() throws ComponentInitializationException, ResolutionException {
        PrincipalAuthenticationMethodAttributeDefinition defn = new PrincipalAuthenticationMethodAttributeDefinition();
        defn.setId("id");
        defn.setLookupStrategy(new Strategy(""));
        defn.initialize();
        Assert.assertFalse(defn.doAttributeDefinitionResolve(null).isPresent());
    }
    
    @Test
    public void testUsual() throws ComponentInitializationException, ResolutionException {
        PrincipalAuthenticationMethodAttributeDefinition defn = new PrincipalAuthenticationMethodAttributeDefinition();
        defn.setId("id");
        defn.setLookupStrategy(new Strategy("Method"));
        defn.initialize();
        
        Optional<Attribute> result = defn.doAttributeDefinitionResolve(null);
        
        Assert.assertEquals(result.get().getValues().size(), 1);
        
        StringAttributeValue value = (StringAttributeValue) result.get().getValues().iterator().next();
        Assert.assertEquals(value.getValue(), "Method");
    }
    
    @Test
    public void testGetterSetter() {
        PrincipalAuthenticationMethodAttributeDefinition defn = new PrincipalAuthenticationMethodAttributeDefinition();
        defn.setId("id");
        Assert.assertNull(defn.getLookupStrategy());
        defn.setLookupStrategy(new Strategy("Method"));
        Assert.assertEquals(((Strategy)defn.getLookupStrategy()).getValue(), "Method");
    }
    
    public class Strategy implements Function<AttributeResolutionContext, String> {

        private final String value;
        
        public Strategy(String what) {
            value = what;
        }
        
        public String getValue() {
            return value;
        }
        
        /** {@inheritDoc} */
        @Nullable public String apply(@Nullable AttributeResolutionContext input) {
            return value;
        }
        
    }

}
