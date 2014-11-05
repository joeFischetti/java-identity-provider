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

package net.shibboleth.idp.attribute.filter.spring;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import net.shibboleth.ext.spring.util.SpringSupport;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.filter.AttributeFilter;
import net.shibboleth.idp.attribute.filter.AttributeFilterException;
import net.shibboleth.idp.attribute.filter.context.AttributeFilterContext;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.service.ServiceException;

import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.google.common.collect.Sets;

/** Test the attribute resolver service. */
public class AttributeFilterServiceTest {

    /** The attributes to be filtered. */
    private Map<String, IdPAttribute> attributesToBeFiltered;

    /** The service configuration dir. */
    private final static String SERVICE_CONFIG_DIR = "net/shibboleth/idp/attribute/filter/spring/";

    /**
     * Instantiate a new service.
     * 
     * @param name service bean name
     * @param resources configuration resources
     * @return the service
     * @throws ServiceException if an error occurs loading the service
     * @throws ComponentInitializationException
     */
    private static AttributeFilter getFilter(String name) throws ServiceException, ComponentInitializationException {
        final Resource resource = new ClassPathResource(SERVICE_CONFIG_DIR + name);
        final GenericApplicationContext context =
                SpringSupport.newContext(name, Collections.singletonList(resource),
                        Collections.<BeanPostProcessor> emptyList(),
                        Collections.<ApplicationContextInitializer> emptyList(), null);
        final AttributeFilterServiceStrategy strategy = new AttributeFilterServiceStrategy();
        strategy.setId("ID");
        strategy.initialize();
        return (AttributeFilter) strategy.apply(context);
    }

    @BeforeClass protected void setUp() throws Exception {

        attributesToBeFiltered = new HashMap<>();

        IdPAttribute firstName = new IdPAttribute("firstName");
        firstName.setValues(Collections.singleton(new StringAttributeValue("john")));
        attributesToBeFiltered.put(firstName.getId(), firstName);

        IdPAttribute lastName = new IdPAttribute("lastName");
        lastName.setValues(Collections.singleton(new StringAttributeValue("smith")));
        attributesToBeFiltered.put(lastName.getId(), lastName);

        IdPAttribute email = new IdPAttribute("email");
        email.setValues(Sets.newHashSet(new StringAttributeValue("jsmith@example.edu"), new StringAttributeValue(
                "john.smith@example.edu")));
        attributesToBeFiltered.put(email.getId(), email);

        IdPAttribute affiliation = new IdPAttribute("affiliation");
        affiliation.setValues(Sets.newHashSet(new StringAttributeValue("employee"), new StringAttributeValue("staff"),
                new StringAttributeValue("illegalValue")));

        attributesToBeFiltered.put(affiliation.getId(), affiliation);
    }

    @Test public void testPolicy2() throws ServiceException, AttributeFilterException, ComponentInitializationException {

        final AttributeFilter filter = getFilter("policy2.xml");

        AttributeFilterContext filterContext = new AttributeFilterContext();
        filterContext.setPrefilteredIdPAttributes(attributesToBeFiltered.values());

        filter.filterAttributes(filterContext);

        Map<String, IdPAttribute> filteredAttributes = filterContext.getFilteredIdPAttributes();

        Assert.assertEquals(1, filteredAttributes.size());

        Assert.assertNull(filteredAttributes.get("firstName"));

        Assert.assertNull(filteredAttributes.get("lastName"));

        Assert.assertNull(filteredAttributes.get("email"));

        Assert.assertEquals(2, filteredAttributes.get("affiliation").getValues().size(), 2);

        Assert.assertTrue(filteredAttributes.get("affiliation").getValues()
                .contains(new StringAttributeValue("employee")));

        Assert.assertTrue(filteredAttributes.get("affiliation").getValues().contains(new StringAttributeValue("staff")));

    }

    @Test public void testPolicy3() throws ServiceException, AttributeFilterException, ComponentInitializationException {

        final AttributeFilter filter = getFilter("policy3.xml");

        AttributeFilterContext filterContext = new AttributeFilterContext();
        filterContext.setPrefilteredIdPAttributes(attributesToBeFiltered.values());
        filter.filterAttributes(filterContext);

        Map<String, IdPAttribute> filteredAttributes = filterContext.getFilteredIdPAttributes();

        Assert.assertEquals(filteredAttributes.size(), 1);

        Assert.assertNull(filteredAttributes.get("firstName"));

        Assert.assertNull(filteredAttributes.get("lastName"));

        Assert.assertEquals(filteredAttributes.get("email").getValues().size(), 2);

        Assert.assertTrue(filteredAttributes.get("email").getValues()
                .contains(new StringAttributeValue("jsmith@example.edu")));

        Assert.assertTrue(filteredAttributes.get("email").getValues()
                .contains(new StringAttributeValue("john.smith@example.edu")));

        Assert.assertNull(filteredAttributes.get("affiliation"));
    }

    @Test public void testPolicy4() throws ServiceException, AttributeFilterException, ComponentInitializationException {

        common45("policy4.xml");
    }

    @Test public void testPolicy5() throws ServiceException, AttributeFilterException, ComponentInitializationException {

        common45("policy5.xml");
    }

    private void common45(String file) throws ServiceException, AttributeFilterException,
            ComponentInitializationException {

        final AttributeFilter filter = getFilter(file);

        AttributeFilterContext filterContext = new AttributeFilterContext();
        filterContext.setPrefilteredIdPAttributes(attributesToBeFiltered.values());

        filter.filterAttributes(filterContext);

        Map<String, IdPAttribute> filteredAttributes = filterContext.getFilteredIdPAttributes();

        Assert.assertEquals(1, filteredAttributes.size());

        Assert.assertNull(filteredAttributes.get("firstName"));

        Assert.assertNull(filteredAttributes.get("lastName"));

        Assert.assertNull(filteredAttributes.get("email"));

        Assert.assertEquals(2, filteredAttributes.get("affiliation").getValues().size(), 2);

        Assert.assertTrue(filteredAttributes.get("affiliation").getValues()
                .contains(new StringAttributeValue("employee")));

        Assert.assertTrue(filteredAttributes.get("affiliation").getValues().contains(new StringAttributeValue("staff")));

    }

    @Test public void deny1() throws ServiceException, AttributeFilterException, ComponentInitializationException {
        denyTest("deny1.xml");
    }

    @Test public void deny2() throws ServiceException, AttributeFilterException, ComponentInitializationException {
        denyTest("deny2.xml");
    }

    private void denyTest(String file) throws ServiceException, AttributeFilterException,
            ComponentInitializationException {
        final AttributeFilter filter = getFilter(file);

        AttributeFilterContext filterContext = new AttributeFilterContext();
        filterContext.setPrefilteredIdPAttributes(attributesToBeFiltered.values());

        filter.filterAttributes(filterContext);

        Map<String, IdPAttribute> filteredAttributes = filterContext.getFilteredIdPAttributes();

        Assert.assertEquals(1, filteredAttributes.size());

        Assert.assertNull(filteredAttributes.get("firstName"));

        Assert.assertNull(filteredAttributes.get("lastName"));

        Assert.assertNull(filteredAttributes.get("email"));

        Assert.assertEquals(2, filteredAttributes.get("affiliation").getValues().size(), 1);

        Assert.assertTrue(filteredAttributes.get("affiliation").getValues()
                .contains(new StringAttributeValue("employee")));

    }

}
