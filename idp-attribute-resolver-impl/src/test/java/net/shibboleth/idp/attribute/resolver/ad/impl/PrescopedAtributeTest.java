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

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.testng.annotations.Test;

import net.shibboleth.idp.attribute.ByteAttributeValue;
import net.shibboleth.idp.attribute.EmptyAttributeValue;
import net.shibboleth.idp.attribute.EmptyAttributeValue.EmptyType;
import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.ScopedStringAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.resolver.AttributeDefinition;
import net.shibboleth.idp.attribute.resolver.DataConnector;
import net.shibboleth.idp.attribute.resolver.ResolutionException;
import net.shibboleth.idp.attribute.resolver.ResolverDataConnectorDependency;
import net.shibboleth.idp.attribute.resolver.ResolverTestSupport;
import net.shibboleth.idp.attribute.resolver.context.AttributeResolutionContext;
import net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImpl;
import net.shibboleth.idp.attribute.resolver.impl.AttributeResolverImplTest;
import net.shibboleth.idp.saml.impl.TestSources;
import net.shibboleth.utilities.java.support.collection.LazySet;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.component.DestroyedComponentException;
import net.shibboleth.utilities.java.support.component.UninitializedComponentException;
import net.shibboleth.utilities.java.support.logic.ConstraintViolationException;

/**
 * Test for prescoped attribute definitions.
 */
public class PrescopedAtributeTest {
    /** The name. resolve to */
    private static final String TEST_ATTRIBUTE_NAME = "prescoped";

    private static final String DELIMITER = "@";

    /**
     * Test regexp. The test Data Connector provides an input attribute "at1" with values at1-Data and at1-Connector. We
     * can feed these into the prescoped, looking for '-'
     * 
     * @throws ResolutionException on resolution issues.
     * @throws ComponentInitializationException if any of our initializtions failed (which it shouldn't)
     */
    @Test public void preScoped() throws ResolutionException, ComponentInitializationException {

        // Set the dependency on the data connector
        final  ResolverDataConnectorDependency depend = new ResolverDataConnectorDependency(TestSources.STATIC_CONNECTOR_NAME);
        depend.setAttributeNames(Collections.singletonList(TestSources.DEPENDS_ON_ATTRIBUTE_NAME_CONNECTOR));
        final PrescopedAttributeDefinition attrDef = new PrescopedAttributeDefinition();
        attrDef.setId(TEST_ATTRIBUTE_NAME);
        attrDef.setScopeDelimiter("-");
        attrDef.setDataConnectorDependencies(Collections.singleton(depend));
        attrDef.initialize();

        // And resolve
        final Set<DataConnector> connectorSet = new LazySet<>();
        connectorSet.add(TestSources.populatedStaticConnector());

        final Set<AttributeDefinition> attributeSet = new LazySet<>();
        attributeSet.add(attrDef);

        final AttributeResolverImpl resolver = AttributeResolverImplTest.newAttributeResolverImpl("foo", attributeSet, connectorSet);
        resolver.initialize();

        final AttributeResolutionContext context = new AttributeResolutionContext();
        resolver.resolveAttributes(context);
        final Collection<?> f = context.getResolvedIdPAttributes().get(TEST_ATTRIBUTE_NAME).getValues();

        assertEquals(f.size(), 2);
        assertTrue(f.contains(new ScopedStringAttributeValue("at1", "Data")));
        assertTrue(f.contains(new ScopedStringAttributeValue("at1", "Connector")));
    }

    /**
     * Test the prescoped attribute resolve when there are no matches.
     * 
     * @throws ResolutionException if resolution fails.
     * @throws ComponentInitializationException if any of our initializations failed (which it shouldn't)
     */
    @Test public void preScopedNoValues() throws ResolutionException, ComponentInitializationException {

        // Set the dependency on the data connector
        final Set<ResolverDataConnectorDependency> dependencySet = new LazySet<>();
        final  ResolverDataConnectorDependency depend = new ResolverDataConnectorDependency(TestSources.STATIC_CONNECTOR_NAME);
        depend.setAttributeNames(Collections.singletonList(TestSources.DEPENDS_ON_ATTRIBUTE_NAME_CONNECTOR));
        dependencySet.add(depend);
        final PrescopedAttributeDefinition attrDef = new PrescopedAttributeDefinition();
        attrDef.setId(TEST_ATTRIBUTE_NAME);
        attrDef.setScopeDelimiter(DELIMITER);
        attrDef.setDataConnectorDependencies(dependencySet);
        attrDef.initialize();

        // And resolve
        final Set<DataConnector> connectorSet = new LazySet<>();
        connectorSet.add(TestSources.populatedStaticConnector());

        final Set<AttributeDefinition> attributeSet = new LazySet<>();
        attributeSet.add(attrDef);

        final AttributeResolverImpl resolver = AttributeResolverImplTest.newAttributeResolverImpl("foo", attributeSet, connectorSet);
        resolver.initialize();

        final AttributeResolutionContext context = new AttributeResolutionContext();
        try {
            resolver.resolveAttributes(context);
            fail();
        } catch (final ResolutionException e) {
            // OK
        }
    }

    @Test public void invalidValueType() throws ComponentInitializationException {
        final IdPAttribute attr = new IdPAttribute(ResolverTestSupport.EPA_ATTRIB_ID);
        attr.setValues(Collections.singletonList(new ByteAttributeValue(new byte[] {1, 2, 3})));

        final AttributeResolutionContext resolutionContext =
                ResolverTestSupport.buildResolutionContext(ResolverTestSupport.buildDataConnector("connector1", attr));

        final PrescopedAttributeDefinition attrDef = new PrescopedAttributeDefinition();
        attrDef.setId(TEST_ATTRIBUTE_NAME);
        attrDef.setScopeDelimiter("@");
        final  ResolverDataConnectorDependency depend = new ResolverDataConnectorDependency("connector1");
        depend.setAttributeNames(Collections.singletonList(ResolverTestSupport.EPA_ATTRIB_ID));
        attrDef.setDataConnectorDependencies(Collections.singleton(depend));
        attrDef.initialize();

        try {
            attrDef.resolve(resolutionContext);
            fail("Invalid type");
        } catch (final ResolutionException e) {
            //
        }
    }
    
    @Test public void nullValueType() throws ComponentInitializationException, ResolutionException {
        final List<IdPAttributeValue> values = new ArrayList<>(4);
        values.add(new StringAttributeValue("one@two"));
        values.add(new EmptyAttributeValue(EmptyType.NULL_VALUE));
        values.add(new StringAttributeValue("three@four"));
        values.add(new EmptyAttributeValue(EmptyType.ZERO_LENGTH_VALUE));
        final IdPAttribute attr = new IdPAttribute(ResolverTestSupport.EPA_ATTRIB_ID);

        attr.setValues(values);

        final AttributeResolutionContext resolutionContext =
                ResolverTestSupport.buildResolutionContext(ResolverTestSupport.buildDataConnector("connector1", attr));
        
        final  ResolverDataConnectorDependency depend = new ResolverDataConnectorDependency("connector1");
        depend.setAttributeNames(Collections.singletonList(ResolverTestSupport.EPA_ATTRIB_ID));

        final PrescopedAttributeDefinition attrDef = new PrescopedAttributeDefinition();
        attrDef.setId(TEST_ATTRIBUTE_NAME);
        attrDef.setScopeDelimiter("@");
        attrDef.setDataConnectorDependencies(Collections.singleton(depend));
        attrDef.initialize();
        final IdPAttribute result = attrDef.resolve(resolutionContext);
        
        final Collection<?> f = result.getValues();

        assertEquals(f.size(), 2);
        assertTrue(f.contains(new ScopedStringAttributeValue("one", "two")));
        assertTrue(f.contains(new ScopedStringAttributeValue("three", "four")));

    }


    @Test public void emptyValueType() throws ResolutionException, ComponentInitializationException {
        // Set the dependency on the data connector
        final Set<ResolverDataConnectorDependency> dependencySet = new LazySet<>();
        final  ResolverDataConnectorDependency depend = new ResolverDataConnectorDependency(TestSources.STATIC_CONNECTOR_NAME);
        depend.setAttributeNames(Collections.singletonList(TestSources.DEPENDS_ON_ATTRIBUTE_NAME_CONNECTOR));
        dependencySet.add(depend);
        final PrescopedAttributeDefinition attrDef = new PrescopedAttributeDefinition();
        attrDef.setId(TEST_ATTRIBUTE_NAME);
        // delimiter that will produce an empty value
        attrDef.setScopeDelimiter("at1-");
        attrDef.setDataConnectorDependencies(dependencySet);
        attrDef.initialize();

        // And resolve
        final Set<DataConnector> connectorSet = new LazySet<>();
        connectorSet.add(TestSources.populatedStaticConnector());

        final Set<AttributeDefinition> attributeSet = new LazySet<>();
        attributeSet.add(attrDef);

        final AttributeResolverImpl resolver = AttributeResolverImplTest.newAttributeResolverImpl("foo", attributeSet, connectorSet);
        resolver.initialize();

        final AttributeResolutionContext context = new AttributeResolutionContext();
        resolver.resolveAttributes(context);

        final Collection<?> f = context.getResolvedIdPAttributes().get(TEST_ATTRIBUTE_NAME).getValues();

        // 2 empty attribute values are produced, but they get de-duped into a single value
        assertEquals(f.size(), 1);
        assertEquals(f.iterator().next(), EmptyAttributeValue.ZERO_LENGTH);
    }

    @Test public void initDestroyParms() throws ResolutionException, ComponentInitializationException {

        PrescopedAttributeDefinition attrDef = new PrescopedAttributeDefinition();
        final  ResolverDataConnectorDependency depend = new ResolverDataConnectorDependency("connector1");
        depend.setAttributeNames(Collections.singletonList(ResolverTestSupport.EPA_ATTRIB_ID));
        final Set<ResolverDataConnectorDependency> pluginDependencies = Collections.singleton(depend);
        attrDef.setDataConnectorDependencies(pluginDependencies);
        attrDef.setId(TEST_ATTRIBUTE_NAME);

        try {
            attrDef.setScopeDelimiter(null);
            fail("set null delimiter");
        } catch (final ConstraintViolationException e) {
            // OK
        }

        attrDef = new PrescopedAttributeDefinition();
        attrDef.setId(TEST_ATTRIBUTE_NAME);
        assertNotNull(attrDef.getScopeDelimiter());
        attrDef.setScopeDelimiter(DELIMITER);
        try {
            attrDef.initialize();
            fail("no Dependency - should fail");
        } catch (final ComponentInitializationException e) {
            // OK
        }
        attrDef.setDataConnectorDependencies(pluginDependencies);

        try {
            attrDef.resolve(new AttributeResolutionContext());
            fail("resolve not initialized");
        } catch (final UninitializedComponentException e) {
            // OK
        }
        attrDef.initialize();

        assertEquals(attrDef.getScopeDelimiter(), DELIMITER);

        try {
            attrDef.resolve(null);
            fail("Null context not allowed");
        } catch (final ConstraintViolationException e) {
            // OK
        }

        attrDef.destroy();
        try {
            attrDef.initialize();
            fail("Init after destroy");
        } catch (final DestroyedComponentException e) {
            // OK
        }
        try {
            attrDef.resolve(new AttributeResolutionContext());
            fail("Resolve after destroy");
        } catch (final DestroyedComponentException e) {
            // OK
        }
        try {
            attrDef.setScopeDelimiter(DELIMITER);
            fail("Set Delimiter after destroy");
        } catch (final DestroyedComponentException e) {
            // OK
        }
    }
}
