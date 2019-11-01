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

package net.shibboleth.idp.saml.saml2.profile.config;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.profile.logic.NoConfidentialityMessageChannelPredicate;
import org.opensaml.profile.logic.NoIntegrityMessageChannelPredicate;

import com.google.common.base.Predicates;

import net.shibboleth.utilities.java.support.annotation.constraint.NonnullElements;
import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import net.shibboleth.utilities.java.support.annotation.constraint.NotLive;
import net.shibboleth.utilities.java.support.logic.Constraint;
import net.shibboleth.utilities.java.support.logic.FunctionSupport;
import net.shibboleth.utilities.java.support.primitive.StringSupport;

/** Configuration support for SAML 2 Single Logout. */
public class SingleLogoutProfileConfiguration extends AbstractSAML2ArtifactAwareProfileConfiguration {

    /** ID for this profile configuration. */
    @Nonnull @NotEmpty public static final String PROFILE_ID = "http://shibboleth.net/ns/profiles/saml2/logout";

    /** Predicate used to determine if SOAP-based requests should be signed. */
    @Nonnull private Predicate<MessageContext> signSOAPRequestsPredicate;
    
    /** Predicate used to determine if SOAP-based requests should use client TLS. */
    @Nonnull private Predicate<MessageContext> clientTLSSOAPRequestsPredicate;
    
    /** Lookup function to supply qualifiedNameIDFormats property. */
    @Nonnull private Function<ProfileRequestContext,Collection<String>> qualifiedNameIDFormatsLookupStrategy;
    
    /** Constructor. */
    public SingleLogoutProfileConfiguration() {
        this(PROFILE_ID);
    }
    
    /**
     * Constructor.
     * 
     * @param profileId unique ID for this profile
     */
    protected SingleLogoutProfileConfiguration(@Nonnull @NotEmpty final String profileId) {
        super(profileId);
        setSignRequestsPredicate(new NoIntegrityMessageChannelPredicate());
        setSignResponsesPredicate(new NoIntegrityMessageChannelPredicate());
        setEncryptNameIDsPredicate(new NoConfidentialityMessageChannelPredicate());

        signSOAPRequestsPredicate = new org.opensaml.messaging.logic.NoIntegrityMessageChannelPredicate();
        clientTLSSOAPRequestsPredicate = new org.opensaml.messaging.logic.NoIntegrityMessageChannelPredicate().negate();
        
        qualifiedNameIDFormatsLookupStrategy = FunctionSupport.constant(null);
    }

    /**
     * Get whether SOAP-based requests should be signed.
     * 
     * @param messageContext current message context
     * 
     * @return whether SOAP-based requests should be signed
     * 
     * @since 4.0.0
     */
    public boolean isSignSOAPRequests(@Nullable final MessageContext messageContext) {
        return signSOAPRequestsPredicate.test(messageContext);
    }

    /**
     * Set whether SOAP-based requests should be signed.
     * 
     * @param flag flag to set
     * 
     * @since 4.0.0
     */
    public void setSignSOAPRequests(final boolean flag) {
        signSOAPRequestsPredicate = flag ? Predicates.alwaysTrue() : Predicates.alwaysFalse();
    }
    
    /**
     * Set the predicate used to determine if SOAP-based requests should be signed.
     * 
     * @param predicate the predicate
     * 
     * @since 4.0.0
     */
    public void setSignSOAPRequestsPredicate(@Nonnull final Predicate<MessageContext> predicate) {
        signSOAPRequestsPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to determine SOAP-based signing cannot be null");
    }

    /**
     * Get whether SOAP-based requests should use client TLS.
     * 
     * @param messageContext current message context
     * 
     * @return whether SOAP-based requests should use client TLS
     * 
     * @since 4.0.0
     */
    public boolean isClientTLSSOAPRequests(@Nullable final MessageContext messageContext) {
        return clientTLSSOAPRequestsPredicate.test(messageContext);
    }
    
    /**
     * Set whether SOAP-based requests should use client TLS.
     * 
     * @param flag flag to set
     * 
     * @since 4.0.0
     */
    public void setClientTLSSOAPRequests(final boolean flag) {
        clientTLSSOAPRequestsPredicate = flag ? Predicates.alwaysTrue() : Predicates.alwaysFalse();
    }
    
    /**
     * Set the predicate used to determine if SOAP-based requests should use client TLS.
     * 
     * @param predicate the predicate
     * 
     * @since 4.0.0
     */
    public void setClientTLSSOAPRequestsPredicate(@Nonnull final Predicate<MessageContext> predicate) {
        clientTLSSOAPRequestsPredicate = Constraint.isNotNull(predicate, 
                "Predicate used to determine SOAP-based client TLS use cannot be null");
    }
    
    /**
     * Get a collection of {@link org.opensaml.saml.saml2.core.NameID} Format values for which the use of
     * the NameQualifier and SPNameQualifier attributes is defined to allow default/implicit values
     * derived from the asserting and relying parties.
     * 
     * <p>In the core standard, only the {@link org.opensaml.saml.saml2.core.NameIDType.PERSISTENT} and
     * {@link org.opensaml.saml.saml2.core.NameIDType.TRANSIENT} Formats are defined in this manner. This
     * setting identifies <strong>additional</strong> Formats that should be handled in this way.</p>
     * 
     * @param profileRequestContext current profile request context
     * 
     * @return additional Formats for which defaulting of qualifiers is permissable
     * 
     * @since 3.4.0
     */
    @Nonnull @NonnullElements @NotLive public Collection<String> getQualifiedNameIDFormats(
            @Nullable final ProfileRequestContext profileRequestContext) {
        final Collection<String> formats = qualifiedNameIDFormatsLookupStrategy.apply(profileRequestContext);
        if (formats != null) {
            return List.copyOf(formats);
        }
        return Collections.emptyList();
    }

    /**
     * Set a collection of {@link org.opensaml.saml.saml2.core.NameID} Format values for which the use of
     * the NameQualifier and SPNameQualifier attributes is defined to allow default/implicit values
     * derived from the asserting and relying parties.
     * 
     * <p>In the core standard, only the {@link org.opensaml.saml.saml2.core.NameIDType.PERSISTENT} and
     * {@link org.opensaml.saml.saml2.core.NameIDType.TRANSIENT} Formats are defined in this manner. This
     * setting identifies <strong>additional</strong> Formats that should be handled in this way.</p>
     * 
     * @param formats additional Formats for which defaulting of qualifiers is permissable
     * 
     * @since 3.4.0
     */
    public void setQualifiedNameIDFormats(@Nullable @NonnullElements final Collection<String> formats) {
        if (formats == null || formats.isEmpty()) {
            qualifiedNameIDFormatsLookupStrategy = FunctionSupport.constant(null);
        } else {
            qualifiedNameIDFormatsLookupStrategy =
                    FunctionSupport.constant(List.copyOf(StringSupport.normalizeStringCollection(formats)));
        }
    }

    /**
     * Set a lookup strategy for the Format values for which the use of the NameQualifier and SPNameQualifier
     * attributes is defined to allow default/implicit values derived from the asserting and relying parties.
     *
     * @param strategy  lookup strategy
     * 
     * @since 3.4.0
     */
    public void setQualifiedNameIDFormatsLookupStrategy(
            @Nonnull final Function<ProfileRequestContext,Collection<String>> strategy) {
        qualifiedNameIDFormatsLookupStrategy = Constraint.isNotNull(strategy, "Lookup strategy cannot be null");
    }
    
}