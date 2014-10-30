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

package net.shibboleth.idp.cas.flow;

import org.springframework.webflow.execution.Event;

/**
 * CAS protocol flow event identifiers.
 *
 * @author Marvin S. Addison
 */
public enum Events {

    /** Active IdP session not found. */
    SessionNotFound,

    /** Active IdP session found. */
    SessionFound,

    /** CAS protocol renew flag specified to force authentication. */
    RenewRequested,

    /** CAS protocol gateway flag specified to skip authentication. */
    GatewayRequested,

    /** Successful service ticket validation. */
    ServiceTicketValidated,

    /** Successful proxy ticket validation. */
    ProxyTicketValidated,

    /** Generic success event. */
    Success,

    /** Generic failure event. */
    Failure,

    /** Generic proceed event. */
    Proceed;

    /**
     * Converts enumeration name to an identifier suitable for a Spring Webflow event identifier.
     *
     * @return Events enumeration name with first letter lower-cased.
     */
    public String id() {
        return this.name().substring(0, 1).toLowerCase() + this.name().substring(1);
    }


    /**
     * Creates a Spring webflow event whose ID is given by {@link #id()}.
     *
     * @param source Event source.
     *
     * @return Spring webflow event.
     */
    public Event event(final Object source) {
        return new Event(source, id());
    }
}
