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

package net.shibboleth.idp.profile.spring.relyingparty.security.credential;

import java.io.File;
import java.io.IOException;
import java.security.KeyException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.annotation.Nullable;
import javax.crypto.SecretKey;

import org.cryptacular.util.KeyPairUtil;
import org.opensaml.security.crypto.KeySupport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.FatalBeanException;
import org.springframework.beans.factory.BeanCreationException;

import com.google.common.io.Files;

/**
 * Factory bean for BasicFilesystem Credentials.
 */
public class BasicFilesystemCredentialFactoryBean extends AbstractBasicCredentialFactoryBean {

    /** log. */
    private final Logger log = LoggerFactory.getLogger(BasicFilesystemCredentialFactoryBean.class);

    /** Configured public key Info. */
    @Nullable private File publicKeyInfo;

    /** Configured private key Info. */
    @Nullable private File privateKeyInfo;

    /** Configured secret key Info. */
    @Nullable private File secretKeyInfo;

    /**
     * Get the information used to generate the public key.
     * 
     * @return Returns the info.
     */
    @Nullable public File getPublicKeyInfo() {
        return publicKeyInfo;
    }

    /**
     * Set the information used to generate the public key.
     * 
     * @param info The info to set.
     */
    public void setPublicKeyInfo(@Nullable File info) {
        publicKeyInfo = info;
    }

    /**
     * Get the information used to generate the private key.
     * 
     * @return Returns the info.
     */
    @Nullable public File getPrivateKeyInfo() {
        return privateKeyInfo;
    }

    /**
     * Set the information used to generate the private key.
     * 
     * @param info The info to set.
     */
    public void setPrivateKeyInfo(@Nullable File info) {
        privateKeyInfo = info;
    }

    /**
     * Get the information used to generate the secret key.
     * 
     * @return Returns the info.
     */
    @Nullable public File getSecretKeyInfo() {
        return secretKeyInfo;
    }

    /**
     * Set the information used to generate the secret key.
     * 
     * @param info The info to set.
     */
    public void setSecretKeyInfo(@Nullable File info) {
        secretKeyInfo = info;
    }

    /** {@inheritDoc} */
    @Override @Nullable protected PublicKey getPublicKey() {
        if (null == getPublicKeyInfo()) {
            return null;
        }
        try {
            return KeyPairUtil.readPublicKey(getPublicKeyInfo());
        } catch (IOException e) {
            log.error("{}: Could not decode public key: {}", getConfigDescription(), e);
            throw new FatalBeanException("Could not decode public key", e);
        }
    }

    /** {@inheritDoc} */
    @Override @Nullable protected PrivateKey getPrivateKey() {
        if (null == getPrivateKeyInfo()) {
            return null;
        }
        try {
            return KeySupport.decodePrivateKey(getPrivateKeyInfo(), getSecretKeyPassword());
        } catch (KeyException e) {
            log.error("{}: Could not decode private key: {}", e);
            throw new BeanCreationException("Could not decode private key", getConfigDescription(), e);
        }
    }

    /** {@inheritDoc} */
    @Override @Nullable protected SecretKey getSecretKey() {
        if (null == getSecretKeyInfo()) {
            return null;
        }
        try {
            return KeySupport.decodeSecretKey(Files.toByteArray(getSecretKeyInfo()), getSecretKeyPassword());
        } catch (KeyException | IOException e) {
            log.error("{} Could not decode secret key: {}", getConfigDescription(), e);
            throw new BeanCreationException("Could not decode secret key", e);
        }
    }
}
