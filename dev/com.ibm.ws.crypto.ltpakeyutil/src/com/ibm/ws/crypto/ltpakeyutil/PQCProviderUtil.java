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

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;

/**
 * Utility class for detecting and managing Post-Quantum Cryptography (PQC) providers.
 * 
 * <p>This class provides methods to detect the availability of PQC algorithms
 * in the Java runtime environment and to determine which cryptographic provider
 * should be used for PQC operations.
 * 
 * <p>Supported providers include:
 * <ul>
 * <li>OpenJCEPlus - IBM Semeru 17+ (distributed platforms)</li>
 * <li>IBMJCEPlus - IBM Java 8 (distributed platforms)</li>
 * <li>IBMJCECCA - IBM Semeru 17+ (z/OS)</li>
 * <li>SunJCE - OpenJDK 24+ (all platforms)</li>
 * </ul>
 */
public final class PQCProviderUtil {
    
    // Provider names
    private static final String PROVIDER_OPENJCEPLUS = "OpenJCEPlus";
    private static final String PROVIDER_IBMJCEPLUS = "IBMJCEPlus";
    private static final String PROVIDER_IBMJCECCA = "IBMJCECCA";
    private static final String PROVIDER_SUNJCE = "SunJCE";
    
    // Algorithm names
    private static final String ALGORITHM_ML_DSA_65 = "ML-DSA-65";
    private static final String ALGORITHM_ML_DSA_87 = "ML-DSA-87";
    
    // Cached provider information
    private static volatile String cachedPQCProvider = null;
    private static volatile Boolean pqcAvailable = null;
    
    /**
     * Private constructor to prevent instantiation.
     */
    private PQCProviderUtil() {
        // Utility class
    }
    
    /**
     * Checks if PQC (Post-Quantum Cryptography) is available in the current runtime.
     * 
     * <p>This method checks for the availability of ML-DSA algorithms in any of the
     * supported cryptographic providers. The result is cached for performance.
     * 
     * @return true if PQC is available, false otherwise
     */
    public static boolean isPQCAvailable() {
        if (pqcAvailable != null) {
            return pqcAvailable;
        }
        
        synchronized (PQCProviderUtil.class) {
            if (pqcAvailable != null) {
                return pqcAvailable;
            }
            
            // TODO: Implement actual provider detection
            // For now, return false as PQC providers are not yet available
            pqcAvailable = detectPQCProvider() != null;
            return pqcAvailable;
        }
    }
    
    /**
     * Gets the name of the PQC provider to use.
     * 
     * <p>This method returns the name of the first available provider that supports
     * ML-DSA algorithms. The result is cached for performance.
     * 
     * @return the provider name, or null if no PQC provider is available
     */
    public static String getPQCProvider() {
        if (cachedPQCProvider != null) {
            return cachedPQCProvider;
        }
        
        synchronized (PQCProviderUtil.class) {
            if (cachedPQCProvider != null) {
                return cachedPQCProvider;
            }
            
            cachedPQCProvider = detectPQCProvider();
            return cachedPQCProvider;
        }
    }
    
    /**
     * Detects which PQC provider is available in the current runtime.
     * 
     * @return the provider name, or null if no PQC provider is available
     */
    private static String detectPQCProvider() {
        // Check OpenJCEPlus (IBM Semeru 17+)
        if (checkProviderSupport(PROVIDER_OPENJCEPLUS)) {
            return PROVIDER_OPENJCEPLUS;
        }
        
        // Check IBMJCEPlus (IBM Java 8)
        if (checkProviderSupport(PROVIDER_IBMJCEPLUS)) {
            return PROVIDER_IBMJCEPLUS;
        }
        
        // Check IBMJCECCA (z/OS)
        if (checkProviderSupport(PROVIDER_IBMJCECCA)) {
            return PROVIDER_IBMJCECCA;
        }
        
        // Check SunJCE (OpenJDK 24+)
        if (checkProviderSupport(PROVIDER_SUNJCE)) {
            return PROVIDER_SUNJCE;
        }
        
        return null;
    }
    
    /**
     * Checks if a specific provider supports ML-DSA algorithms.
     * 
     * @param providerName the name of the provider to check
     * @return true if the provider supports ML-DSA, false otherwise
     */
    private static boolean checkProviderSupport(String providerName) {
        Provider provider = Security.getProvider(providerName);
        if (provider == null) {
            return false;
        }
        
        // Try to get ML-DSA-65 signature instance
        try {
            Signature.getInstance(ALGORITHM_ML_DSA_65, provider);
            return true;
        } catch (NoSuchAlgorithmException e) {
            // Provider doesn't support ML-DSA
            return false;
        }
    }
    
    /**
     * Resets the cached provider information.
     * 
     * <p>This method should be called if the security providers are modified
     * at runtime (e.g., during testing).
     */
    public static void resetCache() {
        synchronized (PQCProviderUtil.class) {
            cachedPQCProvider = null;
            pqcAvailable = null;
        }
    }
    
    /**
     * Gets information about the PQC provider.
     * 
     * @return a string describing the PQC provider status
     */
    public static String getProviderInfo() {
        if (!isPQCAvailable()) {
            return "PQC not available - no supported provider found";
        }
        
        String provider = getPQCProvider();
        Provider p = Security.getProvider(provider);
        if (p != null) {
            return "PQC available via " + provider + " " + p.getVersionStr();
        }
        
        return "PQC available via " + provider;
    }
}

// Made with Bob
