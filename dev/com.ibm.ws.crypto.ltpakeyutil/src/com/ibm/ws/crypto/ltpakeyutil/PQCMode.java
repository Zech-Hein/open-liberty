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
 * Enumeration of Post-Quantum Cryptography (PQC) modes for LTPA tokens.
 * 
 * <p>This enum defines the different modes in which PQC can be used with LTPA:
 * <ul>
 * <li>DISABLED - No PQC, uses classical RSA only (backward compatible)</li>
 * <li>HYBRID - Uses both RSA and ML-DSA signatures (recommended for transition)</li>
 * <li>PURE - Uses only ML-DSA signatures (future quantum-safe mode)</li>
 * </ul>
 * 
 * @see <a href="https://csrc.nist.gov/projects/post-quantum-cryptography">NIST PQC Project</a>
 */
public enum PQCMode {
    /**
     * PQC is disabled. Uses classical RSA signatures only.
     * This is the default mode for backward compatibility.
     */
    DISABLED,
    
    /**
     * Hybrid mode uses both RSA and ML-DSA signatures.
     * Both signatures must verify successfully for token validation.
     * This is the recommended mode during the transition to PQC.
     */
    HYBRID,
    
    /**
     * Pure PQC mode uses only ML-DSA signatures.
     * This mode provides quantum resistance without classical crypto overhead.
     * Use this mode only when all systems support PQC.
     */
    PURE;
    
    /**
     * Parse a string value into a PQCMode enum.
     * 
     * @param value the string value to parse (case-insensitive)
     * @return the corresponding PQCMode, or DISABLED if invalid
     */
    public static PQCMode fromString(String value) {
        if (value == null) {
            return DISABLED;
        }
        
        try {
            return valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return DISABLED;
        }
    }
    
    /**
     * Check if PQC is enabled in this mode.
     * 
     * @return true if mode is HYBRID or PURE, false if DISABLED
     */
    public boolean isPQCEnabled() {
        return this != DISABLED;
    }
    
    /**
     * Check if RSA signatures are required in this mode.
     * 
     * @return true if mode is DISABLED or HYBRID, false if PURE
     */
    public boolean requiresRSA() {
        return this != PURE;
    }
    
    /**
     * Check if PQC signatures are required in this mode.
     * 
     * @return true if mode is HYBRID or PURE, false if DISABLED
     */
    public boolean requiresPQC() {
        return this == HYBRID || this == PURE;
    }
}

// Made with Bob
