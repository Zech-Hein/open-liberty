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

import java.security.PublicKey;

/**
 * Represents an ML-DSA (Module-Lattice-Based Digital Signature Algorithm) public key.
 * 
 * <p>ML-DSA is a post-quantum digital signature algorithm standardized in FIPS 204.
 * This class encapsulates the public key used for verifying LTPA tokens with quantum-resistant
 * cryptography.
 * 
 * <p>The encoding format is specific to LTPA and may differ from standard encodings.
 * 
 * @see <a href="https://doi.org/10.6028/NIST.FIPS.204">FIPS 204: ML-DSA</a>
 */
public final class MLDSAPublicKey implements PublicKey {
    
    private static final long serialVersionUID = 1L;
    
    private final byte[][] rawKey;
    private final String algorithm;
    private final int securityLevel;
    
    /**
     * Constructs an ML-DSA public key.
     * 
     * @param rawKey the raw key material in LTPA-specific format
     * @param algorithm the algorithm name (e.g., "ML-DSA-65", "ML-DSA-87")
     * @param securityLevel the security level in bits (128, 192, or 256)
     */
    public MLDSAPublicKey(byte[][] rawKey, String algorithm, int securityLevel) {
        if (rawKey == null || rawKey.length == 0) {
            throw new IllegalArgumentException("Raw key cannot be null or empty");
        }
        if (algorithm == null || algorithm.isEmpty()) {
            throw new IllegalArgumentException("Algorithm cannot be null or empty");
        }
        if (securityLevel != 128 && securityLevel != 192 && securityLevel != 256) {
            throw new IllegalArgumentException("Security level must be 128, 192, or 256");
        }
        
        this.rawKey = rawKey.clone();
        this.algorithm = algorithm;
        this.securityLevel = securityLevel;
    }
    
    /**
     * Gets the raw key material in LTPA-specific format.
     * 
     * @return a clone of the raw key array
     */
    public byte[][] getRawKey() {
        return rawKey.clone();
    }
    
    /**
     * Gets the security level of this key.
     * 
     * @return the security level in bits (128, 192, or 256)
     */
    public int getSecurityLevel() {
        return securityLevel;
    }
    
    @Override
    public String getAlgorithm() {
        return algorithm;
    }
    
    @Override
    public String getFormat() {
        return "LTPA";
    }
    
    @Override
    public byte[] getEncoded() {
        // TODO: Implement proper encoding for ML-DSA public key
        // This should follow LTPA key file format for v3.0
        throw new UnsupportedOperationException("ML-DSA public key encoding not yet implemented");
    }
    
    @Override
    public String toString() {
        return "MLDSAPublicKey[algorithm=" + algorithm + ", securityLevel=" + securityLevel + "]";
    }
}

// Made with Bob
