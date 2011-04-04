/*
 * Copyright 2010 University Corporation for Advanced Internet Development, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.shibboleth.idp.attribute.resolver;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import net.jcip.annotations.ThreadSafe;
import net.shibboleth.idp.AbstractComponent;
import net.shibboleth.idp.ComponentValidationException;
import net.shibboleth.idp.attribute.Attribute;

import org.opensaml.util.StringSupport;
import org.opensaml.util.collections.LazyList;
import org.opensaml.util.collections.LazyMap;
import org.opensaml.util.collections.LazySet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//TODO perf metrics

/** A component that resolves the attributes for a particular subject. */
@ThreadSafe
public class AttributeResolver extends AbstractComponent {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(AttributeResolver.class);

    /** Attribute definitions defined for this resolver. */
    private Map<String, BaseAttributeDefinition> attributeDefinitions;

    /** Data connectors defined for this resolver. */
    private Map<String, BaseDataConnector> dataConnectors;

    /**
     * Constructor.
     * 
     * @param id the unique ID for this resolver
     */
    public AttributeResolver(final String id) {
        super(id);
        attributeDefinitions = Collections.emptyMap();
        dataConnectors = Collections.emptyMap();
    }

    /**
     * Gets the unmodifiable collection of attribute definitions for this resolver. This collection is never null nor
     * contains any null elements.
     * 
     * @return attribute definitions loaded in to this resolver
     */
    public Map<String, BaseAttributeDefinition> getAttributeDefinitions() {
        return attributeDefinitions;
    }

    /**
     * Sets the collection of attribute definitions for this resolver.
     * 
     * @param definitions definition to set, may be null or contain null elements
     */
    public void setAttributeDefinition(final Collection<BaseAttributeDefinition> definitions) {
        if (definitions == null || definitions.isEmpty()) {
            attributeDefinitions = Collections.emptyMap();
            return;
        }

        final LazyMap<String, BaseAttributeDefinition> newDefinitions = new LazyMap<String, BaseAttributeDefinition>();
        for (BaseAttributeDefinition definition : definitions) {
            if (definition != null) {
                newDefinitions.put(definition.getId(), definition);
            }
        }

        attributeDefinitions = Collections.unmodifiableMap(newDefinitions);
    }

    /**
     * Gets the unmodifiable collection of data connectors for this resolver. This collection is never null nor contains
     * any null elements.
     * 
     * @return data connectors loaded in to this resolver
     */
    public Map<String, BaseDataConnector> getDataConnectors() {
        return dataConnectors;
    }

    /**
     * Sets the collection of data connectors for this resolver.
     * 
     * @param connectors connectors to set, may be null or contain null elements
     */
    public void setDataConnectors(final Collection<BaseDataConnector> connectors) {
        if (connectors == null || connectors.isEmpty()) {
            dataConnectors = Collections.emptyMap();
            return;
        }

        final LazyMap<String, BaseDataConnector> newConnectors = new LazyMap<String, BaseDataConnector>();
        for (BaseDataConnector connector : connectors) {
            if (connector != null) {
                newConnectors.put(connector.getId(), connector);
            }
        }

        dataConnectors = Collections.unmodifiableMap(newConnectors);
    }

    /**
     * Resolves the attribute for the give request. Note, if attributes are requested,
     * {@link AttributeResolutionContext#getRequestedAttributes()}, the resolver will <strong>not</strong> fail if they
     * can not be resolved. This information serves only as a hint to the resolver to, potentially, optimize the
     * resolution of attributes.
     * 
     * @param resolutionContext the attribute resolution context that identifies the request subject and accumulates the
     *            resolved attributes
     * 
     * @throws AttributeResolutionException thrown if there is a problem resolving the attributes for the subject
     */
    public void resolveAttributes(final AttributeResolutionContext resolutionContext)
            throws AttributeResolutionException {
        log.debug("Attribute Resolver {}: initiating attribute resolution", getId());

        if (attributeDefinitions.size() == 0) {
            log.debug("Attribute Resolver {}: no attribute definition available, no attributes were resolved", getId());
            return;
        }

        final Collection<String> attributeIds = getToBeResolvedAttributes(resolutionContext);
        log.debug("Attribute Resolver {}: attempting to resolve the following attribute definitions {}", getId(),
                attributeIds);

        for (String attributeId : attributeIds) {
            resolveAttributeDefinition(attributeId, resolutionContext);
        }

        log.debug("Attribute Resolver {}: finalizing resolved attributes", getId());
        finalizeResolvedAttributes(resolutionContext);

        log.debug("Attribute Resolver {}: final resolved attribute collection: {}", getId(), resolutionContext
                .getResolvedAttributes().keySet());
        return;
    }

    /**
     * Gets the list of attributes, identified by IDs, that should be resolved. If the
     * {@link AttributeResolutionContext#getRequestedAttributes()} is not empty then those attributes are the ones to be
     * resolved, otherwise all registered attribute definitions are to be resolved.
     * 
     * @param resolutionContext current resolution context
     * 
     * @return list of attributes, identified by IDs, that should be resolved
     */
    protected Collection<String> getToBeResolvedAttributes(final AttributeResolutionContext resolutionContext) {
        final Collection<String> attributeIds = new LazyList<String>();

        for (Attribute<?> requestedAttribute : resolutionContext.getRequestedAttributes()) {
            attributeIds.add(requestedAttribute.getId());
        }

        // if no attributes requested, then resolve everything
        if (attributeIds.isEmpty()) {
            attributeIds.addAll(attributeDefinitions.keySet());
        }

        return attributeIds;
    }

    /**
     * Resolve the {@link BaseAttributeDefinition} which has the specified ID.
     * 
     * The results of the resolution are stored in the given {@link AttributeResolutionContext}.
     * 
     * @param attributeId id of the attribute definition to resolve
     * @param resolutionContext resolution context that we are working in
     * 
     * @throws AttributeResolutionException if unable to resolve the requested attribute definition
     */
    protected void resolveAttributeDefinition(final String attributeId,
            final AttributeResolutionContext resolutionContext) throws AttributeResolutionException {
        log.debug("Attribute Resolver {}: beginning to resolve attribute definition {}", getId(), attributeId);

        if (resolutionContext.getResolvedAttributeDefinitions().containsKey(attributeId)) {
            log.debug("Attribute Resolver {}: attribute definition {} was already resolved, nothing to do", getId(),
                    attributeId);
            return;
        }

        final BaseAttributeDefinition definition = attributeDefinitions.get(attributeId);
        if (definition == null) {
            log.debug("Attribute Resolver {}: no attribute definition was registered with ID {}, nothing to do",
                    getId(), attributeId);
            return;
        }

        resolveDependencies(definition, resolutionContext);

        Attribute resolvedAttribute = null;

        try {
            log.debug("Attribute Resolver {}: resolving attribute definition {}", getId(), attributeId);
            resolvedAttribute = definition.resolve(resolutionContext);
        } catch (AttributeResolutionException e) {
            if (definition.isPropagateResolutionExceptions()) {
                log.debug(
                        "Attribute Resolver {}: attribute definition {} produced the following error but was configured not to propogate it.",
                        new Object[] {getId(), attributeId, e,});
            } else {
                throw e;
            }
        }

        if (resolvedAttribute == null) {
            log.debug("Attribute Resolver {}: attribute definition {} produced no attribute", getId(), attributeId);
        } else {
            log.debug("Attribute Resolver {}: attribute definition {} produced an attribute with {} values",
                    new Object[] {getId(), attributeId, resolvedAttribute.getValues().size()});
        }
        resolutionContext.recordAttributeDefinitionResolution(definition, resolvedAttribute);
    }

    /**
     * Resolve the {@link DataConnector} which has the specified ID.
     * 
     * The results of the resolution are stored in the given {@link AttributeResolutionContext}.
     * 
     * @param connectorId id of the data connector to resolve
     * @param resolutionContext resolution context that we are working in
     * 
     * @throws AttributeResolutionException if unable to resolve the requested connector
     */
    protected void resolveDataConnector(final String connectorId, final AttributeResolutionContext resolutionContext)
            throws AttributeResolutionException {
        log.debug("Attribute Resolver {}: beginning to resolve data connector {}", getId(), connectorId);

        if (resolutionContext.getResolvedDataConnectors().containsKey(connectorId)) {
            log.debug("Attribute Resolver {}: data connector {} was already resolved, nothing to do", getId(),
                    connectorId);
            return;
        }

        final BaseDataConnector connector = dataConnectors.get(connectorId);
        if (connector == null) {
            log.debug("Attribute Resolver {}: no data connector was registered with ID {}, nothing to do", getId(),
                    connectorId);
            return;
        }

        resolveDependencies(connector, resolutionContext);

        Map<String, Attribute<?>> resolvedAttributes = null;
        try {
            log.debug("Attribute Resolver {}: resolving data connector {}", getId(), connectorId);
            resolvedAttributes = connector.resolve(resolutionContext);
        } catch (AttributeResolutionException e) {
            final String failoverDataConnectorId = connector.getFailoverDataConnectorId();
            if (failoverDataConnectorId != null) {
                resolveDataConnector(failoverDataConnectorId, resolutionContext);
            } else {
                if (connector.isPropagateResolutionExceptions()) {
                    log.debug(
                            "Attribute Resolver {}: data connector {} produced the following error but was configured not to propogate it.",
                            new Object[] {getId(), connectorId, e});
                } else {
                    throw e;
                }
            }
        }

        if (resolvedAttributes == null) {
            log.debug("Attribute Resolver {}: data connector {} produced no attributes", getId(), connectorId);
        } else {
            log.debug("Attribute Resolver {}: data connector {} resolved the following attributes {}", new Object[] {
                    getId(), connectorId, resolvedAttributes.keySet(),});
        }
        resolutionContext.recordDataConnectorResolution(connector, resolvedAttributes);
    }

    /**
     * Resolves all the dependencies for a given plugin.
     * 
     * @param plugin plugin whose dependencies should be resolved
     * @param resolutionContext current resolution context
     * 
     * @throws AttributeResolutionException thrown if there is a problem resolving a dependency
     */
    protected void resolveDependencies(final BaseResolverPlugin<?> plugin,
            final AttributeResolutionContext resolutionContext) throws AttributeResolutionException {

        if (plugin.getDependencies().isEmpty()) {
            return;
        }

        log.debug("Attribute Resolver {}: resolving dependencies for {}", getId(), plugin.getId());

        String pluginId;
        for (ResolverPluginDependency dependency : plugin.getDependencies()) {
            pluginId = dependency.getDependencyPluginId();
            if (attributeDefinitions.containsKey(pluginId)) {
                resolveAttributeDefinition(pluginId, resolutionContext);
            } else if (dataConnectors.containsKey(pluginId)) {
                resolveDataConnector(pluginId, resolutionContext);
            } else {
                throw new AttributeResolutionException("Plugin " + plugin.getId() + " contains a depedency on plugin "
                        + pluginId + " and that plugin does not exist.");
            }
        }

        log.debug("Attribute Resolver {}: finished resolving dependencies for {}", getId(), plugin.getId());
    }

    /**
     * Finalizes the set of resolved attributes and places them in the {@link AttributeResolutionContext}. The result of
     * each {@link BaseAttributeDefinition} resolution is inspected. If the result is not null, a dependency-only
     * attribute, or an attribute that contains no values then it becomes part of the final set of resolved attributes.
     * 
     * @param resolutionContext current resolution context
     */
    protected void finalizeResolvedAttributes(final AttributeResolutionContext resolutionContext) {
        final LazySet<Attribute<?>> resolvedAttributes = new LazySet<Attribute<?>>();

        Attribute<?> resolvedAttribute;
        for (ResolvedAttributeDefinition definition : resolutionContext.getResolvedAttributeDefinitions().values()) {
            resolvedAttribute = definition.getResolvedAttribute();

            // remove nulls
            if (resolvedAttribute == null) {
                log.debug("Attribute Resolver {}: removing result of attribute definition {}, it's null", getId(),
                        definition.getId());
                continue;
            }

            // remove dependency-only attributes
            if (definition.isDependencyOnly()) {
                log.debug(
                        "Attribute Resolver {}: removing result of attribute definition {}, it's marked as depdency only",
                        getId(), definition.getId());
                continue;
            }

            // remove any nulls or duplicate attribute values
            cleanResolvedAttributeValues(resolvedAttribute);

            // remove value-less attributes
            if (resolvedAttribute.getValues().size() == 0) {
                log.debug(
                        "Attribute Resolver {}: removing result of attribute definition {}, it's attribute contains no values",
                        getId(), definition.getId());
                continue;
            }

            resolvedAttributes.add(resolvedAttribute);
        }

        resolutionContext.setResolvedAttributes(resolvedAttributes);
    }

    /**
     * Cleans the values of the given attribute. Currently this entails removal of any nulls or duplicate values.
     * 
     * @param attribute attribute whose values will be cleaned
     */
    protected void cleanResolvedAttributeValues(final Attribute<?> attribute) {
        final Collection<?> values = attribute.getValues();
        if (values.isEmpty()) {
            return;
        }

        final LazySet cleanedValues = new LazySet<Object>();
        for (Object value : values) {
            if (value != null) {
                cleanedValues.add(value);
            }
        }

        attribute.setValues(cleanedValues);
    }

    /**
     * {@inheritDoc}
     * 
     * This method checks if each registered data connector and attribute definition is valid (via
     * {@link BaseResolverPlugin#validate()} and checks to see if there are any loops in the dependency for all
     * registered plugins.
     */
    public void validate() throws ComponentValidationException {
        HashSet<String> dependencyVerifiedPlugins = new HashSet<String>();

        final LazyList<String> invalidDataConnectors = new LazyList<String>();
        for (BaseDataConnector plugin : dataConnectors.values()) {
            log.debug("Attribute resolver {}: checking if data connector {} is valid", getId(), plugin.getId());
            checkPlugInDependencies(plugin.getId(), plugin, dependencyVerifiedPlugins);
            validateDataConnector(plugin, invalidDataConnectors);
        }

        final LazyList<String> invalidAttributeDefinitions = new LazyList<String>();
        for (BaseAttributeDefinition plugin : attributeDefinitions.values()) {
            log.debug("Attribute resolver {}: checking if attribute definition {} is valid", getId(), plugin.getId());
            checkPlugInDependencies(plugin.getId(), plugin, dependencyVerifiedPlugins);
            try {
                plugin.validate();
                log.debug("Attribute resolver {}: attribute definition {} is valid", getId(), plugin.getId());
            } catch (ComponentValidationException e) {
                log.warn("Attribute resolver {}: attribute definition {} is not valid", new Object[] {this.getId(),
                        plugin.getId(), e,});
                invalidAttributeDefinitions.add(plugin.getId());
            }
        }

        if (!invalidDataConnectors.isEmpty() || !invalidAttributeDefinitions.isEmpty()) {
            throw new ComponentValidationException("Attribute resolver " + getId()
                    + ": the following attribute definitions were invalid ["
                    + StringSupport.listToStringValue(invalidAttributeDefinitions, ", ")
                    + "] and the following data connectors were invalid ["
                    + StringSupport.listToStringValue(invalidDataConnectors, ", ") + "]");
        }
    }

    protected boolean validateDataConnector(BaseDataConnector connector, LazyList<String> invalidDataConnectors) {
        try {
            connector.validate();
            log.debug("Attribute resolver {}: data connector {} is valid", getId(), connector.getId());
            return true;
        } catch (ComponentValidationException e) {
            if (connector.getFailoverDataConnectorId() != null) {
                if (invalidDataConnectors.contains(connector.getFailoverDataConnectorId())) {
                    log.warn(
                            "Attribute resolver {}: data connector {} is not valid for the following reason and failover data connector {} has already been found to be inavlid",
                            new Object[] {getId(), connector.getId(), connector.getFailoverDataConnectorId(), e,});
                    invalidDataConnectors.add(connector.getId());
                    return false;
                } else {
                    log.warn(
                            "Attribute resolver {}: data connector {} is not valid for the following reason, checking if failover data connector {} is valid",
                            new Object[] {getId(), connector.getId(), connector.getFailoverDataConnectorId(), e,});
                    return validateDataConnector(dataConnectors.get(connector.getFailoverDataConnectorId()),
                            invalidDataConnectors);
                }
            }

            log.warn("Attribute resolver {}: data connector {} is not valid and has not failover connector",
                    new Object[] {this.getId(), connector.getId(), e,});
            invalidDataConnectors.add(connector.getId());
            return false;
        }
    }

    /**
     * Checks to ensure that there are no circular dependencies or dependencies on non-existent plugins.
     * 
     * @param circularCheckPluginId the ID of the plugin currently being checked for circular dependencies
     * @param plugin current plugin, in the dependency tree of the plugin being checked, that we're currently looking at
     * @param checkedPlugins IDs of plugins that have already been checked and known to be good
     * 
     * @throws ComponentValidationException thrown if there is a dependency loop
     */
    protected void checkPlugInDependencies(final String circularCheckPluginId, final BaseResolverPlugin<?> plugin,
            final Set<String> checkedPlugins) throws ComponentValidationException {
        final String pluginId = plugin.getId();

        BaseResolverPlugin<?> dependencyPlugin;
        for (ResolverPluginDependency dependency : plugin.getDependencies()) {
            if (checkedPlugins.contains(pluginId)) {
                continue;
            }

            if (circularCheckPluginId.equals(dependency.getDependencyPluginId())) {
                throw new ComponentValidationException("Plugin " + circularCheckPluginId
                        + " has a dependency on plugin " + dependency.getDependencyPluginId());
            }

            dependencyPlugin = dataConnectors.get(dependency.getDependencyPluginId());
            if (dependencyPlugin == null) {
                dependencyPlugin = attributeDefinitions.get(dependency.getDependencyPluginId());
            }
            if (dependencyPlugin == null) {
                throw new ComponentValidationException("Plugin " + plugin.getId() + " has a dependency on plugin "
                        + dependency.getDependencyPluginId() + " which does not exist");
            }

            checkPlugInDependencies(circularCheckPluginId, dependencyPlugin, checkedPlugins);
            checkedPlugins.add(pluginId);
        }
    }
}