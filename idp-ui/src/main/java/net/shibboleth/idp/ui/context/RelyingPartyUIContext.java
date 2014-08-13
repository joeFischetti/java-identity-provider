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

package net.shibboleth.idp.ui.context;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

import org.opensaml.messaging.context.BaseContext;
import org.opensaml.saml.ext.saml2mdui.Description;
import org.opensaml.saml.ext.saml2mdui.DisplayName;
import org.opensaml.saml.ext.saml2mdui.UIInfo;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml.saml2.metadata.OrganizationName;
import org.opensaml.saml.saml2.metadata.OrganizationURL;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.ServiceDescription;
import org.opensaml.saml.saml2.metadata.ServiceName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The context which carries the user interface information.
 */
public class RelyingPartyUIContext extends BaseContext {

    /** The log. */
    @Nonnull private final Logger log = LoggerFactory.getLogger(RelyingPartyUIContext.class);

    /** The appropriate {@link EntityDescriptor}. */
    @Nullable private EntityDescriptor rpEntityDescriptor;

    /** The appropriate {@link SPSSODescriptor}. */
    @Nullable private SPSSODescriptor rpSPSSODescriptor;

    /** The appropriate {@link AttributeConsumingService}. */
    @Nullable private AttributeConsumingService rpAttributeConsumingService;

    /** The appropriate {@link UIInfo}. */
    @Nullable private UIInfo rpUIInfo;

    /** The languages that this browser wants to know about. */
    @Nonnull private List<String> browserLanguages;

    /**
     * Get the {@link EntityDescriptor}.
     * 
     * @return Returns the entity.
     */
    @Nullable protected EntityDescriptor getRPEntityDescriptor() {
        return rpEntityDescriptor;
    }

    /**
     * Set the {@link EntityDescriptor}.
     * 
     * @param what what to set.
     */
    public void setRPEntityDescriptor(@Nonnull final EntityDescriptor what) {
        rpEntityDescriptor = Constraint.isNotNull(what, "Injected RP EntityDescriptor cannot be null");
    }

    /**
     * Get the {@link SPSSODescriptor}.
     * 
     * @return Returns the SPSSODescriptor.
     */
    @Nullable protected SPSSODescriptor getRPSPSSODescriptor() {
        return rpSPSSODescriptor;
    }

    /**
     * Set the {@link SPSSODescriptor}.
     * 
     * @param what what to set.
     */
    public void setRPSPSSODescriptor(@Nonnull final SPSSODescriptor what) {
        rpSPSSODescriptor = Constraint.isNotNull(what, "Injected RP EntityDescriptor cannot be null");
    }

    /**
     * Get the {@link AttributeConsumingService} for the request.
     * 
     * @return Returns the SPSSODescriptor.
     */
    @Nullable protected AttributeConsumingService getRPAttributeConsumingService() {
        return rpAttributeConsumingService;
    }

    /**
     * Get the RP {@link UIInfo} associated with the request.
     * 
     * @return the value or null if there is none.
     */
    @Nullable protected UIInfo getRPUInfo() {
        return rpUIInfo;
    }

    /**
     * Set the RP {@link UIInfo} associated with the request.
     * 
     * @param what the value to set.
     */
    public void setRPUInfo(@Nullable final UIInfo what) {
        rpUIInfo = what;
    }

    /**
     * Set the {@link AttributeConsumingService} for the request.
     * 
     * @param what what to set.
     */
    public void setRPAttributeConsumingService(@Nonnull final AttributeConsumingService what) {
        rpAttributeConsumingService =
                Constraint.isNotNull(what, "Injected RP AttributeConsumingService cannot be null");
    }

    /**
     * Set the browser languages.
     * 
     * @param languages the languages to set.
     */
    public void setBrowserLanguages(@Nonnull final List<String> languages) {
        browserLanguages = Constraint.isNotNull(languages, "Language List mustr be non null");
    }

    /**
     * Get the browser languages.
     * 
     * @return the languages.
     */
    @Nonnull protected List<String> getBrowserLanguages() {
        return browserLanguages;
    }

    /**
     * Check to see whether a supplied URL is acceptable, returning the default if it isn't.
     * 
     * @param url the url to look at
     * @param acceptableSchemes the schemes to test against
     * @param defaultValue what to return if the test fails
     * @return the input or the default as appropriate.
     */
    @Nullable private String policeURL(@Nullable final String url,
            @Nonnull @NotEmpty final List<String> acceptableSchemes, @Nullable final String defaultValue) {
        if (null == url) {
            log.trace("Empty Value - returning '{}", defaultValue);
            return defaultValue;
        }

        try {
            final String scheme = new URI(url).getScheme();

            for (final String acceptableScheme : acceptableSchemes) {
                if (acceptableScheme.equals(scheme)) {
                    log.debug("Acceptable Scheme '{}', returning value '{}'", acceptableScheme, url);
                    return url;
                }
            }

            log.warn("The logo URL '{}' contained an invalid scheme (expected '{}'), returning default of '{}'", url,
                    acceptableSchemes, defaultValue);
            return defaultValue;
        } catch (URISyntaxException e) {
            log.warn("The logo URL '{}' contained was not a URL, returning default of '{}'", url, defaultValue);
            return defaultValue;
        }
    }

    /**
     * Police a url found for a logo.
     * 
     * @param url the url to look at
     * @param defaultValue what to return if the test fails
     * @return the input or the default as appropriate
     */
    protected String policyURLLogo(@Nullable final String url, @Nullable final String defaultValue) {
        return policeURL(url, Arrays.asList("http", "https", "data"), defaultValue);
    }

    /**
     * Police a url found for non logo data.
     * 
     * @param url the url to look at
     * @param defaultValue what to return if the test fails
     * @return the input or the default as appropriate
     */
    protected String policyURLNonLogo(@Nullable final String url, @Nullable final String defaultValue) {
        return policeURL(url, Arrays.asList("http", "https", "mailto"), defaultValue);
    }

    /**
     * look at &lt;UIinfo&gt;; if there and if so look for appropriate name.
     * 
     * @param lang - which language to look up
     * @return null or an appropriate name
     */
    @Nullable protected String getNameFromUIInfo(final String lang) {

        if (getRPUInfo() != null) {
            for (final DisplayName name : getRPUInfo().getDisplayNames()) {
                log.trace("Found name in UIInfo, language '{}'", name.getXMLLang());
                if (name.getXMLLang().equals(lang)) {
                    log.debug("Language match, Returning name from UIInfo '{}'", name.getValue());
                    return name.getValue();
                }
            }
        }
        log.trace("No name in UIINFO for '{}'", lang);
        return null;
    }

    /**
     * Look for an &lt;AttributeConsumeService&gt; and if its there look for an appropriate name.
     * 
     * @param lang - which language to look up
     * @return null or an appropriate name
     */
    @Nullable protected String getNameFromAttributeConsumingService(final String lang) {

        if (null == getRPAttributeConsumingService()) {
            return null;
        }

        for (ServiceName name : getRPAttributeConsumingService().getNames()) {
            log.trace("Found name in AttributeConsumingService, language '{}'", name.getXMLLang());
            if (name.getXMLLang().equals(lang)) {
                log.debug("Returning name from AttributeConsumingService '{}", name.getValue());
                return name.getValue();
            }
        }
        log.trace("No name found in AttributeConsumingService for '{}'", lang);
        return null;
    }

    /**
     * If the entityId can look like a host return that, otherwise the entityId in full.
     * 
     * @return either the host or the entityId.
     */
    @Nullable protected String getNameFromEntityId() {

        if (null == getRPEntityDescriptor()) {
            log.trace("No relying party, no Name");
            return null;
        }
        final String spName = getRPEntityDescriptor().getEntityID();

        try {
            final URI entityId = new URI(spName);
            final String scheme = entityId.getScheme();

            if ("http".equals(scheme) || "https".equals(scheme)) {
                log.debug("found matching schema, returning name of '{}'", entityId.getHost());
                return entityId.getHost();
            }
            log.debug("Not a usual schema returning name of '{}'", spName);

            return spName;
        } catch (URISyntaxException e) {
            log.debug("Not a URI returning name of '{}'", spName);
            return spName;
        }
    }

    /**
     * look at &lt;UIInfo&gt; if there and if so look for appropriate description.
     * 
     * @param lang - which language to look up
     * @return null or an appropriate description
     */
    @Nullable protected String getDescriptionFromUIInfo(final String lang) {
        if (getRPUInfo() == null || getRPUInfo().getDescriptions() == null) {
            log.trace("No UIInfo");
            return null;
        }
        for (final Description desc : getRPUInfo().getDescriptions()) {
            log.trace("Found description in UIInfo, language '{}'", desc.getXMLLang());
            if (desc.getXMLLang().equals(lang)) {
                log.trace("Found language match, returning description from UIInfo '{}'", desc.getValue());
                return desc.getValue();
            }
        }
        log.debug("No matching description in UIInfo");
        return null;
    }

    /**
     * look for an &ltAttributeConsumeService&gt and if its there look for an appropriate description.
     * 
     * @param lang - which language to look up
     * @return null or an appropriate description
     */
    @Nullable protected String getDescriptionFromAttributeConsumingService(final String lang) {
        if (getRPAttributeConsumingService() == null) {
            log.trace("No ACS found");
            return null;
        }
        for (final ServiceDescription desc : getRPAttributeConsumingService().getDescriptions()) {
            log.trace("Found name in AttributeConsumingService, language=" + desc.getXMLLang());
            if (desc.getXMLLang().equals(lang)) {
                log.debug("returning name from AttributeConsumingService " + desc.getValue());
                return desc.getValue();
            }
        }
        log.trace("No description in AttributeConsumingService");

        return null;
    }

    /**
     * Get the {@link Organization} from the {@link SPSSODescriptor}, failing that the {@link EntityDescriptor}.
     * 
     * @return the {@link Organization} for the relying party.
     */
    @Nullable protected Organization getOrganization() {
        if (null != getRPSPSSODescriptor() && null != getRPSPSSODescriptor().getOrganization()) {
            return getRPSPSSODescriptor().getOrganization();
        }
        if (null != getRPEntityDescriptor() && null != getRPEntityDescriptor().getOrganization()) {
            return getRPEntityDescriptor().getOrganization();
        }
        return null;
    }

    /**
     * Parser for the contact type.
     * 
     * @param type in value
     * @return the enumeration type. suitably defaulted.
     */
    protected ContactPersonTypeEnumeration getContactType(@Nullable final String type) {
        final String value = StringSupport.trimOrNull(type);
        if (null == value) {
            log.warn("no parameter provided to contactType");
            return ContactPersonTypeEnumeration.SUPPORT;
        }
        if (type.equals(ContactPersonTypeEnumeration.ADMINISTRATIVE.toString())) {
            return ContactPersonTypeEnumeration.ADMINISTRATIVE;
        } else if (type.equals(ContactPersonTypeEnumeration.BILLING.toString())) {
            return ContactPersonTypeEnumeration.BILLING;
        } else if (type.equals(ContactPersonTypeEnumeration.OTHER.toString())) {
            return ContactPersonTypeEnumeration.OTHER;
        } else if (type.equals(ContactPersonTypeEnumeration.SUPPORT.toString())) {
            return ContactPersonTypeEnumeration.SUPPORT;
        } else if (type.equals(ContactPersonTypeEnumeration.TECHNICAL.toString())) {
            return ContactPersonTypeEnumeration.TECHNICAL;
        } else {
            log.warn("parameter provided to contactType: " + type + " is invalid");
            return ContactPersonTypeEnumeration.SUPPORT;
        }
    }

    /**
     * Lookup the specified type of Contact in the RP metadata.
     * 
     * @param contactType what type to look up.
     * @return the {@link ContactPerson} or null.
     */
    @Nullable protected ContactPerson getContactPerson(ContactPersonTypeEnumeration contactType) {
        if (null == getRPEntityDescriptor()) {
            return null;
        }
        final List<ContactPerson> contacts = getRPEntityDescriptor().getContactPersons();
        if (null == contacts || contacts.isEmpty()) {
            log.trace("No Contacts found at all");
            return null;
        }
        for (final ContactPerson contact : contacts) {
            if (contactType == contact.getType()) {
                return contact;
            }
        }
        log.trace("No matching Contacts found at all");
        return null;
    }

    /**
     * Get the service name.
     * 
     * @param defaultValue what to provide if this is an anonymous lookup
     * @return the name
     */
    @Nullable public String getServiceName(@Nullable final String defaultValue) {

        if (getRPEntityDescriptor() == null) {
            log.debug("No relying party, no name, returning '{}'", defaultValue);
            return defaultValue;
        }

        for (final String lang : getBrowserLanguages()) {
            String result;
            result = getNameFromUIInfo(lang);
            if (result != null) {
                return result;
            }

            result = getNameFromAttributeConsumingService(lang);
            if (result != null) {
                return result;
            }
        }
        // failing that just look at the entity name
        return getNameFromEntityId();
    }

    /**
     * Get the service Description.
     * 
     * @param defaultValue what to provide if this is an anonymous lookup
     * @return the name
     */
    @Nullable public String getServiceDescription(@Nullable final String defaultValue) {

        for (final String lang : getBrowserLanguages()) {
            String value = getDescriptionFromUIInfo(lang);
            if (null != value) {
                return value;
            }
            value = getDescriptionFromAttributeConsumingService(lang);
            if (null != value) {
                return value;
            }
        }
        log.debug("No description matching the languages found, returning '{}'", defaultValue);
        return defaultValue;
    }

    /**
     * Look for the &lt;OrganizationDisplayName&gt;.
     * 
     * @param defaultValue what to provide if the lookup fails
     * @return An appropriate string or the default
     */
    @Nullable public String getOrganizationDisplayName(@Nullable final String defaultValue) {
        final Organization org = getOrganization();
        if (null == org || null == org.getDisplayNames() || org.getDisplayNames().isEmpty()) {
            log.debug("No Organization, OrganizationDisplayName or names, returning {}", defaultValue);
            return defaultValue;
        }
        for (final String lang : getBrowserLanguages()) {

            for (final OrganizationDisplayName name : org.getDisplayNames()) {
                if (name.getXMLLang() == null) {
                    continue;
                } else {
                    log.trace("Found OrganizationDisplayName in Organization, language={}", name.getXMLLang());
                }

                if (name.getXMLLang().equals(lang)) {
                    log.debug("returning OrganizationDisplayName from Organization, {}", name.getValue());
                    return name.getValue();
                }
            }
        }
        log.debug("No relevant OrganizationDisplayName in Organization, returning {}", defaultValue);
        return defaultValue;
    }

    /**
     * Look for the &lt;OrganizationName&gt;.
     * 
     * @param defaultValue what to provide if the lookup fails
     * @return An appropriate string or the default
     */
    @Nullable public String getOrganizationName(@Nullable final String defaultValue) {
        final Organization org = getOrganization();
        if (null == org || null == org.getOrganizationNames() || org.getOrganizationNames().isEmpty()) {
            log.debug("No Organization, OrganizationName or names, returning {}", defaultValue);
            return defaultValue;
        }
        for (final String lang : getBrowserLanguages()) {

            for (final OrganizationName name : org.getOrganizationNames()) {
                if (name.getXMLLang() == null) {
                    continue;
                } else {
                    log.trace("Found OrganizationName in Organization, language={}", name.getXMLLang());
                }

                if (name.getXMLLang().equals(lang)) {
                    log.debug("returning OrganizationName from Organization, {}", name.getValue());
                    return name.getValue();
                }
            }
        }
        log.debug("No relevant OrganizationName in Organization, returning {}", defaultValue);
        return defaultValue;
    }

    /**
     * * Look for the &lt;OrganizationURL&gt;.
     * 
     * @param defaultValue what to provide if the lookup fails
     * @return An appropriate string or the default
     */
    public String getOrganizationURL(String defaultValue) {
        final Organization org = getOrganization();
        if (null == org || null == org.getURLs() || org.getURLs().isEmpty()) {
            log.debug("No Organization, OrganizationURL or urls, returning {}", defaultValue);
            return defaultValue;
        }
        for (final String lang : getBrowserLanguages()) {

            for (final OrganizationURL url : org.getURLs()) {
                if (url.getXMLLang() == null) {
                    continue;
                } else {
                    log.trace("Found OrganizationURL in Organization, language={}", url.getXMLLang());
                }

                if (url.getXMLLang().equals(lang)) {
                    log.debug("returning OrganizationURL from Organization, {}", url.getValue());
                    return policyURLNonLogo(url.getValue(), defaultValue);
                }
            }
        }
        log.debug("No relevant OrganizationURL in Organization, returning {}", defaultValue);
        return defaultValue;
    }

    /**
     * look for the &lt;ContactPerson&gt; and within that the SurName.
     * 
     * @param contactType the type of contact to look for
     * @param defaultValue what to provide if the lookup fails
     * @return An appropriate string or the default
     */
    @Nullable public String getSurName(@Nullable String contactType, @Nullable final String defaultValue) {

        final ContactPerson contact = getContactPerson(getContactType(contactType));
        if (null == contact || null == contact.getSurName()) {
            return defaultValue;
        }
        return contact.getSurName().getName();
    }

    /**
     * look for the &lt;ContactPerson&gt; and within that the GivenName.
     * 
     * @param contactType the type of contact to look for
     * @param defaultValue what to provide if the lookup fails
     * @return An appropriate string or the default
     */
    @Nullable public String getGivenName(@Nullable String contactType, @Nullable final String defaultValue) {

        final ContactPerson contact = getContactPerson(getContactType(contactType));
        if (null == contact || null == contact.getGivenName()) {
            return defaultValue;
        }
        return contact.getGivenName().getName();
    }

    /**
     * look for the &lt;ContactPerson&gt; and within that the GivenName.
     * 
     * @param contactType the type of contact to look for
     * @param defaultValue what to provide if the lookup fails
     * @return An appropriate string or the default
     */
    @Nullable public String getEmail(@Nullable String contactType, @Nullable final String defaultValue) {

        final ContactPerson contact = getContactPerson(getContactType(contactType));
        if (null == contact || null == contact.getEmailAddresses() || contact.getEmailAddresses().isEmpty()) {
            return defaultValue;
        }
        return policyURLNonLogo(contact.getEmailAddresses().get(0).getAddress(), defaultValue);
    }

}
