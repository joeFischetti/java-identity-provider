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

package net.shibboleth.idp.saml.profile.config.navigate;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

import net.shibboleth.idp.authn.context.SubjectContext;
import net.shibboleth.idp.authn.principal.ProxyAuthenticationPrincipal;
import net.shibboleth.idp.profile.config.ProfileConfiguration;
import net.shibboleth.idp.profile.context.RelyingPartyContext;
import net.shibboleth.idp.profile.context.navigate.AbstractRelyingPartyLookupFunction;
import net.shibboleth.idp.saml.saml2.profile.config.SAML2ProfileConfiguration;
import net.shibboleth.utilities.java.support.collection.Pair;
import net.shibboleth.utilities.java.support.logic.Constraint;

import org.opensaml.messaging.context.navigate.ChildContextLookup;
import org.opensaml.profile.context.ProfileRequestContext;

/**
 * A function that returns the allowable proxy count and audiences to include in assertions,
 * based on the results of lookup functions for local configuration merged with upstream
 * proxy restrictions to compute a final result in accordance with the standard.
 */
public class ProxyRestrictionLookupFunction extends AbstractRelyingPartyLookupFunction<Pair<Integer,Set<String>>> {

    /** SubjectContext lookup strategy. */
    @Nonnull private Function<ProfileRequestContext,SubjectContext> subjectContextLookupStrategy;
    
    /** Constructor. */
    public ProxyRestrictionLookupFunction() {
        subjectContextLookupStrategy = new ChildContextLookup<>(SubjectContext.class);
    }
    
    /**
     * Set the lookup strategy to locate the {@link SubjectContext}.
     * 
     * @param strategy lookup strategy
     */
    public void setSubjectContextLookupStrategy(
            @Nonnull final Function<ProfileRequestContext,SubjectContext> strategy) {
        subjectContextLookupStrategy = Constraint.isNotNull(strategy, "SubjectContext lookup strategy cannot be null");
    }
    
// Checkstyle: CyclomaticComplexity OFF
    /** {@inheritDoc} */
    @Nullable public Pair<Integer,Set<String>> apply(@Nullable final ProfileRequestContext input) {
        
        Integer proxyCount = null;
        final Set<String> audiences = new HashSet<>();
        
        final RelyingPartyContext rpc = getRelyingPartyContextLookupStrategy().apply(input);
        if (rpc != null) {
            final ProfileConfiguration pc = rpc.getProfileConfig();
            if (pc != null && pc instanceof SAML2ProfileConfiguration) {
                proxyCount = ((SAML2ProfileConfiguration) pc).getProxyCount(input);
                final Set<String> configAudiences = ((SAML2ProfileConfiguration) pc).getProxyAudiences(input);
                if (configAudiences != null) {
                    audiences.addAll(configAudiences);
                }
            }
        }
                
        final SubjectContext sc = subjectContextLookupStrategy.apply(input);
        
        if (sc == null) {
            if (proxyCount != null) {
                proxyCount = Integer.max(0, proxyCount - 1);
            }
            return new Pair<>(proxyCount, audiences);
        }
        
        final Set<ProxyAuthenticationPrincipal> proxieds =
                sc.getSubjects().stream()
                    .map(s -> s.getPrincipals(ProxyAuthenticationPrincipal.class))
                    .flatMap(Set::stream)
                    .collect(Collectors.toUnmodifiableSet());
        for (final ProxyAuthenticationPrincipal p : proxieds) {
            if (p.getProxyCount() != null) {
                if (proxyCount != null) {
                    proxyCount = Integer.min(proxyCount, Integer.max(0, p.getProxyCount() - 1));
                } else {
                    proxyCount = Integer.max(0, p.getProxyCount() - 1);
                }
            }
            
            final Set<String> upstreamAudiences = p.getAudiences();
            if (upstreamAudiences != null && !upstreamAudiences.isEmpty()) {
                if (audiences.isEmpty()) {
                    audiences.addAll(upstreamAudiences);
                } else {
                    audiences.retainAll(upstreamAudiences);
                }
            }
        }
        
        return new Pair<>(proxyCount, audiences);
    }
// Checkstyle: CyclomaticComplexity ON
    
}