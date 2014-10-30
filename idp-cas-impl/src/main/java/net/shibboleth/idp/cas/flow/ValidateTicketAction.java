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

import net.shibboleth.idp.cas.protocol.ProtocolError;
import net.shibboleth.idp.cas.protocol.TicketValidationRequest;
import net.shibboleth.idp.cas.protocol.TicketValidationResponse;
import net.shibboleth.idp.cas.ticket.ServiceTicket;
import net.shibboleth.idp.cas.ticket.Ticket;
import net.shibboleth.idp.cas.ticket.TicketContext;
import net.shibboleth.idp.cas.ticket.TicketService;
import net.shibboleth.idp.profile.AbstractProfileAction;
import net.shibboleth.utilities.java.support.logic.Constraint;
import org.opensaml.profile.context.ProfileRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.webflow.execution.Event;
import org.springframework.webflow.execution.RequestContext;

import javax.annotation.Nonnull;

/**
 * CAS protocol service ticket validation action emits one of the following events based on validation result:
 *
 * <ul>
 *     <li>{@link Events#ServiceTicketValidated serviceTicketValidated}</li>
 *     <li>{@link Events#ProxyTicketValidated proxyTicketValidated}</li>
 *     <li>{@link ProtocolError#InvalidTicketFormat invalidTicketFormat}</li>
 *     <li>{@link ProtocolError#ServiceMismatch serviceMismatch}</li>
 *     <li>{@link ProtocolError#TicketExpired ticketExpired}</li>
 *     <li>{@link ProtocolError#TicketRetrievalError ticketRetrievalError}</li>
 * </ul>
 *
 * <p>
 * In the success case a {@link TicketValidationResponse} message is created and stored
 * as request scope parameter under the key {@value FlowStateSupport#TICKET_VALIDATION_RESPONSE_KEY}.
 *
 * @author Marvin S. Addison
 */
public class ValidateTicketAction
        extends AbstractProfileAction<TicketValidationRequest, TicketValidationResponse> {

    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(ValidateTicketAction.class);

    /** Manages CAS tickets. */
    @Nonnull private final TicketService ticketService;


    /**
     * Creates a new instance.
     *
     * @param ticketService Ticket service component.
     */
    public ValidateTicketAction(@Nonnull TicketService ticketService) {
        this.ticketService = Constraint.isNotNull(ticketService, "TicketService cannot be null");
    }

    @Nonnull
    @Override
    protected Event doExecute(
            final @Nonnull RequestContext springRequestContext,
            final @Nonnull ProfileRequestContext profileRequestContext) {

        final TicketValidationRequest request = FlowStateSupport.getTicketValidationRequest(springRequestContext);
        if (request == null) {
            log.info("TicketValidationRequest not found in flow state.");
            return ProtocolError.IllegalState.event(this);
        }

        final Ticket ticket;
        try {
            final String ticketId = request.getTicket();
            log.debug("Attempting to validate {}", ticketId);
            if (ticketId.startsWith("ST-")) {
                ticket = ticketService.removeServiceTicket(request.getTicket());
            } else if (ticketId.startsWith("PT-")) {
                ticket = ticketService.removeProxyTicket(ticketId);
            } else {
                return ProtocolError.InvalidTicketFormat.event(this);
            }
            if (ticket != null) {
                log.debug("Found and removed {}/{} from ticket store", ticket, ticket.getSessionId());
            }
        } catch (RuntimeException e) {
            log.debug("CAS ticket retrieval failed with error: {}", e);
            return ProtocolError.TicketRetrievalError.event(this);
        }

        if (ticket == null || ticket.getExpirationInstant().isBeforeNow()) {
            return ProtocolError.TicketExpired.event(this);
        }

        if (!ticket.getService().equalsIgnoreCase(request.getService())) {
            log.debug("Service issued for {} does not match {}", ticket.getService(), request.getService());
            return ProtocolError.ServiceMismatch.event(this);
        }

        profileRequestContext.addSubcontext(new TicketContext(ticket));
        FlowStateSupport.setTicketValidationResponse(springRequestContext, new TicketValidationResponse());
        log.info("Successfully validated {} for {}", request.getTicket(), request.getService());
        if (ticket instanceof ServiceTicket) {
            return Events.ServiceTicketValidated.event(this);
        }
        return Events.ProxyTicketValidated.event(this);
    }
}
