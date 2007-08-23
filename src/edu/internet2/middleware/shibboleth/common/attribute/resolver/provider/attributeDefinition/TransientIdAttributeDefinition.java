/*
 * Copyright [2007] [University Corporation for Advanced Internet Development, Inc.]
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

package edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.attributeDefinition;

import java.security.NoSuchAlgorithmException;

import org.joda.time.DateTime;
import org.opensaml.common.IdentifierGenerator;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.util.storage.ExpiringObject;
import org.opensaml.util.storage.StorageService;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.profile.provider.SAMLProfileRequestContext;

/**
 * An attribute definition that generates random identifiers useful for transient subject ids.
 */
public class TransientIdAttributeDefinition extends BaseAttributeDefinition {

    /** Store used to map tokens to principals. */
    private StorageService<String, IdEntry> idStore;

    /** Storage parition in which IDs are stored. */
    private String partition;

    /** Generater of randome, hex-encdoded, tokens. */
    private IdentifierGenerator idGenerator;

    /** Size, in bytes, of the token. */
    private int idSize;

    /** Length, in milliseconds, tokens are valid. */
    private long idLifetime;

    /**
     * Constructor.
     * 
     * @param store store used to map tokens to principals
     * 
     * @throws NoSuchAlgorithmException thrown if the SHA1PRNG, used as the default random number generation algo, is
     *             not supported
     */
    public TransientIdAttributeDefinition(StorageService<String, IdEntry> store) throws NoSuchAlgorithmException {
        idGenerator = new SecureRandomIdentifierGenerator();
        idStore = store;
        partition = "transientId";
        idSize = 16;
        idLifetime = 1000 * 60 * 60 * 4;
    }

    /** {@inheritDoc} */
    protected BaseAttribute doResolve(ShibbolethResolutionContext resolutionContext)
            throws AttributeResolutionException {

        SAMLProfileRequestContext requestContext = resolutionContext.getAttributeRequestContext();
        String token = idGenerator.generateIdentifier(idSize);

        IdEntry tokenEntry = new IdEntry(idLifetime, requestContext.getInboundMessageIssuer(), requestContext
                .getPrincipalName(), token);
        idStore.put(partition, token, tokenEntry);

        BasicAttribute<String> attribute = new BasicAttribute<String>();
        attribute.setId(getId());
        attribute.getValues().add(token);

        return attribute;
    }

    /**
     * Gets the size, in bytes, of the id.
     * 
     * @return size, in bytes, of the id
     */
    public int getIdSize() {
        return idSize;
    }

    /**
     * Sets the size, in bytes, of the id.
     * 
     * @param size size, in bytes, of the id
     */
    public void setIdSize(int size) {
        idSize = size;
    }

    /**
     * Gets the time, in milliseconds, ids are valid.
     * 
     * @return time, in milliseconds, ids are valid
     */
    public long getIdLifetime() {
        return idLifetime;
    }

    /**
     * Sets the time, in milliseconds, ids are valid.
     * 
     * @param lifetime time, in milliseconds, ids are valid
     */
    public void setTokenLiftetime(long lifetime) {
        idLifetime = lifetime;
    }

    /** {@inheritDoc} */
    public void validate() throws AttributeResolutionException {

    }

    /**
     * Storage service entry used to store information associated with a id.
     */
    public class IdEntry implements ExpiringObject {

        /** Time this entry expires. */
        private DateTime expirationTime;

        /** Relying party the token was issed to. */
        private String relyingPartyId;

        /** Principal the token was issused for. */
        private String principalName;

        /** Random token. */
        private String id;

        /**
         * Constructor.
         * 
         * @param lifetime lifetime of the token in milliseconds
         * @param relyingParty relying party the token was issued to
         * @param principal principal the token was issued for
         * @param randomId the random ID token
         */
        public IdEntry(long lifetime, String relyingParty, String principal, String randomId) {
            expirationTime = new DateTime().plus(lifetime);
            relyingPartyId = relyingParty;
            principalName = principal;
            id = randomId;
        }

        /**
         * Gets the principal the token was issued for.
         * 
         * @return principal the token was issued for
         */
        public String getPrincipalName() {
            return principalName;
        }

        /**
         * Gets the relying party the token was issued to.
         * 
         * @return relying party the token was issued to
         */
        public String getRelyingPartyId() {
            return relyingPartyId;
        }

        /**
         * Gets the ID.
         * 
         * @return ID
         */
        public String getId() {
            return id;
        }

        /** {@inheritDoc} */
        public DateTime getExpirationTime() {
            return expirationTime;
        }

        /** {@inheritDoc} */
        public boolean isExpired() {
            return expirationTime.isBeforeNow();
        }

        /** {@inheritDoc} */
        public void onExpire() {

        }
    }
}