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

import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.concurrent.atomic.AtomicReference;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Trivial;

/**
 * Utility class for detecting and managing Post-Quantum Cryptography (PQC) providers.
 * 
 * <p>This class checks for the availability of PQC algorithms (specifically ML-DSA)
 * in the Java security providers. It supports multiple providers:
 * <ul>
 * <li>OpenJCEPlus (IBM Semeru 17+)</li>
 * <li>IBMJCEPlus (IBM Java 8)</li>
 * <li>IBMJCECCA (z/OS)</li>
 * <li>SunJCE (OpenJDK 24+ with PQC support)</li>
 * </ul>
 * 
 * <p>The detection is performed once and cached for performance.
 */
final class PQCProviderUtil {
    
    private static final TraceComponent tc = Tr.register(PQCProviderUtil.class);
    
    // Provider names
    private static final String PROVIDER_OPENJCEPLUS = "OpenJCEPlus";
    private static final String PROVIDER_IBMJCEPLUS = "IBMJCEPlus";
    private static final String PROVIDER_IBMJCECCA = "IBMJCECCA";
    private static final String PROVIDER_SUNJCE = "SunJCE";
    private static final String PROVIDER_BC = "BC"; // BouncyCastle
    private static final String PROVIDER_BCPQC = "BCPQC"; // BouncyCastle PQC
    
    // ML-DSA algorithm names to test
    private static final String[] ML_DSA_ALGORITHMS = {
        "ML-DSA-44",
        "ML-DSA-65", 
        "ML-DSA-87",
        "Dilithium2",
        "Dilithium3",
        "Dilithium5"
    };
    
    // Cached detection results
    private static final AtomicReference<Boolean> pqcAvailable = new AtomicReference<>(null);
    private static final AtomicReference<String> pqcProvider = new AtomicReference<>(null);
    private static final AtomicReference<String> pqcAlgorithm = new AtomicReference<>(null);
    
    /**
     * Private constructor to prevent instantiation.
     */
    private PQCProviderUtil() {
        // Utility class
    }
    
    /**
     * Checks if PQC (ML-DSA) support is available.
     * 
     * <p>This method performs detection on first call and caches the result.
     * 
     * @return true if PQC is available, false otherwise
     */
    @Trivial
    static boolean isPQCAvailable() {
        Boolean cached = pqcAvailable.get();
        if (cached != null) {
            return cached;
        }
        
        // Perform detection
        detectPQCProvider();
        
        return pqcAvailable.get() != null && pqcAvailable.get();
    }
    
    /**
     * Gets the name of the PQC provider.
     * 
     * @return the provider name, or null if PQC is not available
     */
    @Trivial
    static String getPQCProvider() {
        if (!isPQCAvailable()) {
            return null;
        }
        return pqcProvider.get();
    }
    
    /**
     * Gets the ML-DSA algorithm name supported by the provider.
     * 
     * @return the algorithm name, or null if PQC is not available
     */
    @Trivial
    static String getPQCAlgorithm() {
        if (!isPQCAvailable()) {
            return null;
        }
        return pqcAlgorithm.get();
    }
    
    /**
     * Detects PQC provider availability.
     * 
     * <p>This method checks each known provider in priority order:
     * <ol>
     * <li>OpenJCEPlus (preferred for IBM Semeru)</li>
     * <li>IBMJCEPlus (for IBM Java 8)</li>
     * <li>IBMJCECCA (for z/OS)</li>
     * <li>BCPQC (BouncyCastle PQC)</li>
     * <li>BC (BouncyCastle)</li>
     * <li>SunJCE (for OpenJDK with PQC)</li>
     * </ol>
     */
    private static synchronized void detectPQCProvider() {
        // Check if already detected
        if (pqcAvailable.get() != null) {
            return;
        }
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "Detecting PQC provider availability...");
        }
        
        // List all providers for debugging
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Provider[] providers = Security.getProviders();
            Tr.debug(tc, "Available security providers:");
            for (Provider provider : providers) {
                Tr.debug(tc, "  - " + provider.getName() + " " + provider.getVersion());
            }
        }
        
        // Try each provider in priority order
        String[] providerNames = {
            PROVIDER_OPENJCEPLUS,
            PROVIDER_IBMJCEPLUS,
            PROVIDER_IBMJCECCA,
            PROVIDER_BCPQC,
            PROVIDER_BC,
            PROVIDER_SUNJCE
        };
        
        for (String providerName : providerNames) {
            Provider provider = Security.getProvider(providerName);
            if (provider == null) {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Provider not found: " + providerName);
                }
                continue;
            }
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Testing provider: " + providerName);
            }
            
            // Try each ML-DSA algorithm
            for (String algorithm : ML_DSA_ALGORITHMS) {
                if (testAlgorithm(providerName, algorithm)) {
                    pqcAvailable.set(true);
                    pqcProvider.set(providerName);
                    pqcAlgorithm.set(algorithm);
                    
                    if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                        Tr.debug(tc, "PQC support detected: provider=" + providerName + 
                                    ", algorithm=" + algorithm);
                    }
                    
                    Tr.info(tc, "CWWKS4370I: Post-Quantum Cryptography (PQC) support is available using provider {0} with algorithm {1}.", 
                            providerName, algorithm);
                    
                    return;
                }
            }
        }
        
        // No PQC support found
        pqcAvailable.set(false);
        pqcProvider.set(null);
        pqcAlgorithm.set(null);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
            Tr.debug(tc, "No PQC support detected");
        }
        
        Tr.warning(tc, "CWWKS4371W: Post-Quantum Cryptography (PQC) support is not available. " +
                      "LTPA tokens will use classical RSA signatures only. " +
                      "To enable PQC support, install a Java runtime with ML-DSA support.");
    }
    
    /**
     * Tests if a specific algorithm is supported by a provider.
     * 
     * @param providerName the provider name
     * @param algorithm the algorithm name
     * @return true if the algorithm is supported, false otherwise
     */
    private static boolean testAlgorithm(String providerName, String algorithm) {
        try {
            // Test KeyPairGenerator
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm, providerName);
            if (keyGen == null) {
                return false;
            }
            
            // Test Signature
            Signature sig = Signature.getInstance(algorithm, providerName);
            if (sig == null) {
                return false;
            }
            
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Algorithm " + algorithm + " is supported by " + providerName);
            }
            
            return true;
            
        } catch (Exception e) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "Algorithm " + algorithm + " not supported by " + providerName + ": " + e.getMessage());
            }
            return false;
        }
    }
    
    /**
     * Resets the cached detection results.
     * This is primarily for testing purposes.
     */
    @Trivial
    static void resetCache() {
        pqcAvailable.set(null);
        pqcProvider.set(null);
        pqcAlgorithm.set(null);
    }
    
    /**
     * Gets detailed information about PQC support.
     * 
     * @return a string describing PQC support status
     */
    @Trivial
    static String getPQCInfo() {
        if (!isPQCAvailable()) {
            return "PQC support: NOT AVAILABLE";
        }
        
        return String.format("PQC support: AVAILABLE (provider=%s, algorithm=%s)", 
                           pqcProvider.get(), pqcAlgorithm.get());
    }
}

// Made with Bob
