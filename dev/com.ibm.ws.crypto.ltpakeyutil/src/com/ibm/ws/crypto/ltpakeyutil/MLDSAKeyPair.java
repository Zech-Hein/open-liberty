/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.crypto.ltpakeyutil;

/**
 * Represents an ML-DSA key pair (public and private keys).
 * 
 * <p>This class encapsulates both the public and private keys for ML-DSA
 * (Module-Lattice-Based Digital Signature Algorithm), which is used for
 * post-quantum cryptographic signatures in LTPA tokens.
 * 
 * @see MLDSAPublicKey
 * @see MLDSAPrivateKey
 */
public final class MLDSAKeyPair {
    
    private final MLDSAPublicKey publicKey;
    private final MLDSAPrivateKey privateKey;
    
    /**
     * Constructs an ML-DSA key pair.
     * 
     * @param publicKey the ML-DSA public key
     * @param privateKey the ML-DSA private key
     * @throws IllegalArgumentException if either key is null
     */
    public MLDSAKeyPair(MLDSAPublicKey publicKey, MLDSAPrivateKey privateKey) {
        if (publicKey == null) {
            throw new IllegalArgumentException("Public key cannot be null");
        }
        if (privateKey == null) {
            throw new IllegalArgumentException("Private key cannot be null");
        }
        
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }
    
    /**
     * Gets the public key from this key pair.
     * 
     * @return the ML-DSA public key
     */
    public MLDSAPublicKey getPublic() {
        return publicKey;
    }
    
    /**
     * Gets the private key from this key pair.
     * 
     * @return the ML-DSA private key
     */
    public MLDSAPrivateKey getPrivate() {
        return privateKey;
    }
    
    @Override
    public String toString() {
        return "MLDSAKeyPair[algorithm=" + publicKey.getAlgorithm() + 
               ", securityLevel=" + publicKey.getSecurityLevel() + "]";
    }
}

// Made with Bob
