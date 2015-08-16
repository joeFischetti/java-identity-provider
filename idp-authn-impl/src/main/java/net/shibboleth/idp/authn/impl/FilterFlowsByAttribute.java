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

package net.shibboleth.idp.authn.impl;

import java.security.Principal;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.attribute.IdPAttribute;
import net.shibboleth.idp.attribute.IdPAttributeValue;
import net.shibboleth.idp.attribute.StringAttributeValue;
import net.shibboleth.idp.attribute.context.AttributeContext;
import net.shibboleth.idp.authn.AbstractAuthenticationAction;
import net.shibboleth.idp.authn.AuthenticationFlowDescriptor;
import net.shibboleth.idp.authn.context.AuthenticationContext;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.Function;
import com.google.common.base.Functions;

/**
 * An authentication action that filters out potential authentication flows by comparing an {@link IdPAttribute}'s
 * values to the custom principals supported by each flow.
 * 
 * <p>
 * The type of principals is ignored, and only string-based values of an attribute are supported.
 * </p>
 * 
 * @event {@link org.opensaml.profile.action.EventIds#PROCEED_EVENT_ID}
 * @pre <pre>
 * ProfileRequestContext.getSubcontext(AuthenticationContext.class) != null
 * </pre>
 * @post AuthenticationContext.getPotentialFlows() is modified as above.
 */
public class FilterFlowsByAttribute extends AbstractAuthenticationAction {

    /** Class logger. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(FilterFlowsByAttribute.class);

    /** Lookup strategy for locating {@link AttributeContext}. */
    @Nonnull private Function<ProfileRequestContext, AttributeContext> attributeContextLookupStrategy;

    /** The attribute ID to look for. */
    @Nullable private String attributeId;

    /** The attribute to match against. */
    @Nullable private IdPAttribute attribute;

    /** Constructor. */
    public FilterFlowsByAttribute() {
        attributeContextLookupStrategy =
                Functions.compose(new ChildContextLookup<>(AttributeContext.class),
                        new ChildContextLookup<ProfileRequestContext, AuthenticationContext>(
                                AuthenticationContext.class));
    }

    /**
     * Set the lookup strategy for the {@link AttributeContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setAttributeContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext, AttributeContext> strategy) {
        attributeContextLookupStrategy =
                Constraint.isNotNull(strategy, "AttributeContext lookup strategy cannot be null");
    }

    /**
     * Set the attribute ID to look for.
     * 
     * @param id attribute ID to look for
     */
    public void setAttributeId(@Nullable String id) {
        attributeId = StringSupport.trimOrNull(id);
    }

    /** {@inheritDoc} */
    @Override protected boolean doPreExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        if (!super.doPreExecute(profileRequestContext, authenticationContext) || attributeId == null) {
            return false;
        }

        final AttributeContext attributeCtx = attributeContextLookupStrategy.apply(profileRequestContext);
        if (attributeCtx == null) {
            log.debug("{} Request does not contain an AttributeContext, nothing to do", getLogPrefix());
            return false;
        }

        attribute = attributeCtx.getIdPAttributes().get(attributeId);
        if (attribute == null || attribute.getValues().isEmpty()) {
            log.debug("{} Attribute {} has no values, nothing to do", getLogPrefix(), attributeId);
            return false;
        }

        return true;
    }

    /** {@inheritDoc} */
    @Override protected void doExecute(@Nonnull final ProfileRequestContext profileRequestContext,
            @Nonnull final AuthenticationContext authenticationContext) {

        final Map<String, AuthenticationFlowDescriptor> potentialFlows = authenticationContext.getPotentialFlows();

        final Iterator<Entry<String, AuthenticationFlowDescriptor>> descriptorItr =
                potentialFlows.entrySet().iterator();
        while (descriptorItr.hasNext()) {
            final AuthenticationFlowDescriptor descriptor = descriptorItr.next().getValue();
            final String match = getMatch(descriptor);
            if (match != null) {
                log.debug("{} Retaining flow {}, matched custom Principal {}", getLogPrefix(), descriptor.getId(),
                        match);
            } else {
                log.debug("{} Removing flow {}, Principals did not match any attribute values", getLogPrefix(),
                        descriptor.getId());
                descriptorItr.remove();
            }
        }

        if (potentialFlows.size() == 0) {
            log.info("{} No potential authentication flows remain after filtering", getLogPrefix());
        } else {
            log.debug("{} Potential authentication flows left after filtering: {}", getLogPrefix(), potentialFlows);
        }
    }

    /**
     * Compare the flow's custom principal names to the string values of the attribute.
     * 
     * @param flow flow to examine
     * 
     * @return a match between the flow's principal names and the attribute's string values, or null
     */
    @Nullable private String getMatch(@Nonnull final AuthenticationFlowDescriptor flow) {

        log.debug("{} Looking for match for flow {} against values for attribute {}", getLogPrefix(), flow.getId(),
                attribute.getId());
        for (final Principal p : flow.getSupportedPrincipals()) {
            log.debug("{} Comparing principal {} against attribute values {}", getLogPrefix(), p.getName(),
                    attribute.getValues());
            for (final IdPAttributeValue val : attribute.getValues()) {
                if (val instanceof StringAttributeValue && Objects.equals(val.getValue(), p.getName())) {
                    return p.getName();
                }
            }
        }

        return null;
    }

}