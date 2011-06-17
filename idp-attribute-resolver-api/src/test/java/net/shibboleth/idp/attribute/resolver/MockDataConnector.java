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

package net.shibboleth.idp.attribute.resolver;

import java.util.Map;

import net.jcip.annotations.ThreadSafe;
import net.shibboleth.idp.ComponentValidationException;
import net.shibboleth.idp.attribute.Attribute;

/** A data connector that just returns a static collection of attributes. */
@ThreadSafe
public class MockDataConnector extends BaseDataConnector {

    /** Whether this connector fails validation. */
    private boolean invalid;

    /** Static collection of values returned by this connector. */
    private Map<String, Attribute<?>> values;

    /** Exception thrown by {@link #doDataConnectorResolve(AttributeResolutionContext)}. */
    private AttributeResolutionException resolutionException;

    /**
     * Constructor.
     * 
     * @param id unique ID for this data connector
     * @param connectorValues static collection of values returned by this connector
     */
    public MockDataConnector(String id, Map<String, Attribute<?>> connectorValues) {
        super(id);
        values = connectorValues;
    }

    /**
     * Constructor.
     * 
     * @param id id of the data connector
     * @param exception exception thrown by {@link #doDataConnectorResolve(AttributeResolutionContext)}
     */
    public MockDataConnector(final String id, final AttributeResolutionException exception) {
        super(id);
        invalid = false;
        resolutionException = exception;
    }

    /**
     * Sets whether this data connector is considered invalid.
     * 
     * @param isInvalid whether this data connector is considered invalid
     */
    public void setInvalid(boolean isInvalid) {
        invalid = isInvalid;
    }

    /** {@inheritDoc} */
    protected Map<String, Attribute<?>> doDataConnectorResolve(AttributeResolutionContext resolutionContext)
            throws AttributeResolutionException {
        if (resolutionException != null) {
            throw resolutionException;
        }

        return values;
    }

    /** {@inheritDoc} */
    public void validate() throws ComponentValidationException {
        if (invalid) {
            throw new ComponentValidationException();
        }
    }

}