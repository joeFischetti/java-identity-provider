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

package net.shibboleth.idp.saml.relyingparty;

import net.shibboleth.idp.profile.ProfileRequestContext;
import net.shibboleth.idp.relyingparty.AbstractProfileConfiguration;

import org.opensaml.util.Assert;
import org.opensaml.util.criteria.EvaluableCriterion;
import org.opensaml.util.criteria.StaticResponseEvaluableCriterion;

/** Base class for SAML profile configurations. */
public abstract class AbstractSAMLProfileConfiguration extends AbstractProfileConfiguration {

    /** Criteria used to determine if the received assertion should be signed. */
    private EvaluableCriterion<ProfileRequestContext> signedRequestsCriteria;

    /** Criteria used to determine if the generated response should be signed. */
    private EvaluableCriterion<ProfileRequestContext> signResponsesCriteria;

    /** Criteria used to determine if the generated assertion should be signed. */
    private EvaluableCriterion<ProfileRequestContext> signAssertionsCriteria;

    /**
     * Constructor.
     * 
     * @param profileId ID of the the communication profile, never null or empty
     */
    public AbstractSAMLProfileConfiguration(String profileId) {
        super(profileId);
        signedRequestsCriteria =
                (EvaluableCriterion<ProfileRequestContext>) StaticResponseEvaluableCriterion.FALSE_RESPONSE;
        signResponsesCriteria =
                (EvaluableCriterion<ProfileRequestContext>) StaticResponseEvaluableCriterion.TRUE_RESPONSE;
        signAssertionsCriteria =
                (EvaluableCriterion<ProfileRequestContext>) StaticResponseEvaluableCriterion.FALSE_RESPONSE;
    }

    /**
     * Gets the criteria used to determine if the generated assertion should be signed.
     * 
     * @return criteria used to determine if the generated assertion should be signed, never null
     */
    public EvaluableCriterion<ProfileRequestContext> getSignAssertionsCriteria() {
        return signAssertionsCriteria;
    }

    /**
     * Sets the criteria used to determine if the generated assertion should be signed.
     * 
     * @param criteria criteria used to determine if the generated assertion should be signed, never null
     */
    public void setSignAssertionsCriteria(EvaluableCriterion<ProfileRequestContext> criteria) {
        Assert.isNotNull(criteria, "Criteria to determine if assertions should be signed can not be null");
        signAssertionsCriteria = criteria;
    }

    /**
     * Gets the criteria used to determine if the received assertion should be signed.
     * 
     * @return criteria used to determine if the received assertion should be signed, never null
     */
    public EvaluableCriterion<ProfileRequestContext> getSignedRequestsCriteria() {
        return signedRequestsCriteria;
    }

    /**
     * Sets the criteria used to determine if the received assertion should be signed.
     * 
     * @param criteria criteria used to determine if the received assertion should be signed, never null
     */
    public void setSignedRequestsCriteria(EvaluableCriterion<ProfileRequestContext> criteria) {
        Assert.isNotNull(criteria, "Criteria to determine if received requests should be signed can not be null");
        signedRequestsCriteria = criteria;
    }

    /**
     * Gets the criteria used to determine if the generated response should be signed.
     * 
     * @return criteria used to determine if the generated response should be signed, never null
     */
    public EvaluableCriterion<ProfileRequestContext> getSignResponsesCriteria() {
        return signResponsesCriteria;
    }

    /**
     * Sets the criteria used to determine if the generated response should be signed.
     * 
     * @param criteria criteria used to determine if the generated response should be signed, never null
     */
    public void setSignResponsesCriteria(EvaluableCriterion<ProfileRequestContext> criteria) {
        Assert.isNotNull(criteria, "Criteria to determine if responses should be signed can not be null");
        signResponsesCriteria = criteria;
    }
}