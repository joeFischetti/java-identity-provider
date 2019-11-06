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

package net.shibboleth.idp.consent.logic.impl;

import static org.testng.Assert.assertEquals;

import java.util.Collections;
import java.util.List;

import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.EmptyAttributeValue;
import net.shibboleth.idp.consent.impl.ConsentTestingSupport;

/** {@link AttributeValuesHashFunction} unit test. */
public class AttributeValuesHashFunctionTest {

    private AttributeValuesHashFunction function;

    @BeforeMethod public void setUp() {
        function = new AttributeValuesHashFunction();
    }

    @Test public void testNullInput() {
        Assert.assertNull(function.apply(null));
    }

    @Test public void testEmptyInput() {
        Assert.assertNull(function.apply(Collections.emptyList()));
    }
    
    @Test(enabled = true) public void testNullValue() {
        assertEquals(function.apply(List.of(EmptyAttributeValue.NULL)), "GO6W6gt/9+cYhDCPAJSdQnhYbNP07CvgEUNsjTHNWjM=");
        assertEquals(function.apply(List.of(EmptyAttributeValue.ZERO_LENGTH)), "b3sJLxUOXzXC263DWVp0F/l5fxfxJxKuJYGpKCtjhaw=");
    }

    @Test public void testSingleValue() {
        final String hash = function.apply(ConsentTestingSupport.newAttributeMap().get("attribute1").getValues());
        assertEquals(hash, "yePBj0hcjLihhDtDb//R/ymyw2CHZAUreX/4RupmSXM=");
    }

    @Test public void testMultipleValues() {
        final String hash = function.apply(ConsentTestingSupport.newAttributeMap().get("attribute2").getValues());
        assertEquals(hash, "xxuA06hGJ1DcJ4JSaWiBXXGfcRr6oxHM5jaURXBBnbA=");
    }

}
