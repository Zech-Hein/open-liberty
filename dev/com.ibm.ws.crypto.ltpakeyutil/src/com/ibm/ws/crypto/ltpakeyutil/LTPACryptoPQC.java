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

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;
import com.ibm.websphere.ras.annotation.Trivial;

/**
 * Extension of LTPACrypto to support Post-Quantum Cryptography (PQC) operations.
 * 
 * <p>This class provides methods for:
 * <ul>
 * <li>Generating ML-DSA key pairs</li>
 * <li>Signing data with ML-DSA</li>
 * <li>Verifying ML-DSA signatures</li>
 * <li>Hybrid operations (RSA + ML-DSA)</li>
 * </ul>
 * 
 * <p>All methods in this class are designed to work with the existing LTPACrypto
 * infrastructure while adding PQC capabilities.
 * 
 * <p><b>Implementation Notes:</b>
 * <ul>
 * <li>Requires a PQC-capable Java provider (OpenJCEPlus, IBMJCEPlus, IBMJCECCA, or SunJCE with PQC support)</li>
 * <li>ML-DSA algorithms follow NIST FIPS 204 standard</li>
 * <li>Hybrid mode provides both classical (RSA) and quantum-resistant (ML-DSA) security</li>
 * </ul>
 */
final class LTPACryptoPQC {
    
    private static final TraceComponent tc = Tr.register(LTPACryptoPQC.class);
    
    // ML-DSA algorithm names (NIST FIPS 204)
    private static final String ML_DSA_44 = "ML-DSA-44";  // Security level 2 (128-bit)
    private static final String ML_DSA_65 = "ML-DSA-65";  // Security level 3 (192-bit)
    private static final String ML_DSA_87 = "ML-DSA-87";  // Security level 5 (256-bit)
    
    // Alternative algorithm names (some providers may use these)
    private static final String DILITHIUM2 = "Dilithium2";
    private static final String DILITHIUM3 = "Dilithium3";
    private static final String DILITHIUM5 = "Dilithium5";
    
    // Security levels
    private static final int SECURITY_LEVEL_128 = 128;
    private static final int SECURITY_LEVEL_192 = 192;
    private static final int SECURITY_LEVEL_256 = 256;
    
    /**
     * Private constructor to prevent instantiation.
     */
    private LTPACryptoPQC() {
        // Utility class
    }
    
    /**
     * Generates an ML-DSA key pair.
     * 
     * <p>This method attempts to generate an ML-DSA key pair using the available PQC provider.
     * It tries multiple algorithm names to support different provider implementations.
     * 
     * @param securityLevel the security level (128, 192, or 256 bits)
     * @return an ML-DSA key pair
     * @throws NoSuchAlgorithmException if ML-DSA is not supported
     * @throws NoSuchProviderException if no PQC provider is available
     * @throws IllegalArgumentException if security level is invalid
     */
    @Trivial
    static MLDSAKeyPair generateMLDSAKeyPair(int securityLevel) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "generateMLDSAKeyPair", securityLevel);
        }
        
        // Validate security level
        if (securityLevel != SECURITY_LEVEL_128 && 
            securityLevel != SECURITY_LEVEL_192 && 
            securityLevel != SECURITY_LEVEL_256) {
            throw new IllegalArgumentException("Invalid security level: " + securityLevel + 
                                             ". Must be 128, 192, or 256.");
        }
        
        // Check PQC availability
        if (!PQCProviderUtil.isPQCAvailable()) {
            NoSuchProviderException e = new NoSuchProviderException("No PQC provider available");
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "generateMLDSAKeyPair", e);
            }
            throw e;
        }
        
        // Determine algorithm based on security level
        String[] algorithms = getAlgorithmNames(securityLevel);
        String providerName = PQCProviderUtil.getPQCProvider();
        
        KeyPair keyPair = null;
        NoSuchAlgorithmException lastException = null;
        
        // Try each algorithm name until one works
        for (String algorithm : algorithms) {
            try {
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Attempting to generate key pair with algorithm: " + algorithm);
                }
                
                KeyPairGenerator keyGen;
                if (providerName != null) {
                    keyGen = KeyPairGenerator.getInstance(algorithm, providerName);
                } else {
                    keyGen = KeyPairGenerator.getInstance(algorithm);
                }
                
                // Initialize with secure random
                keyGen.initialize(securityLevel, new SecureRandom());
                keyPair = keyGen.generateKeyPair();
                
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Successfully generated key pair with algorithm: " + algorithm);
                }
                break;
                
            } catch (NoSuchAlgorithmException e) {
                lastException = e;
                if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                    Tr.debug(tc, "Algorithm not supported: " + algorithm);
                }
                // Try next algorithm
            }
        }
        
        if (keyPair == null) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "generateMLDSAKeyPair", lastException);
            }
            throw lastException != null ? lastException : 
                new NoSuchAlgorithmException("No ML-DSA algorithm found for security level " + securityLevel);
        }
        
        // Convert to LTPA format
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        
        // Wrap the encoded key bytes in a byte[][] array for LTPA format
        byte[][] privateKeyArray = new byte[][] { privateKey.getEncoded() };
        byte[][] publicKeyArray = new byte[][] { publicKey.getEncoded() };
        
        MLDSAPrivateKey ltpaPrivateKey = new MLDSAPrivateKey(
            privateKeyArray,
            privateKey.getAlgorithm(),
            securityLevel
        );
        
        MLDSAPublicKey ltpaPublicKey = new MLDSAPublicKey(
            publicKeyArray,
            publicKey.getAlgorithm(),
            securityLevel
        );
        
        MLDSAKeyPair result = new MLDSAKeyPair(ltpaPublicKey, ltpaPrivateKey);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "generateMLDSAKeyPair", "Key pair generated successfully");
        }
        
        return result;
    }
    
    /**
     * Signs data using ML-DSA.
     * 
     * @param data the data to sign
     * @param privateKey the ML-DSA private key
     * @return the signature bytes
     * @throws NoSuchAlgorithmException if ML-DSA is not supported
     * @throws NoSuchProviderException if no PQC provider is available
     * @throws InvalidKeyException if the key is invalid
     * @throws SignatureException if signing fails
     */
    @Trivial
    protected static byte[] signMLDSA(byte[] data, MLDSAPrivateKey privateKey) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "signMLDSA", "data length: " + data.length);
        }
        
        if (!PQCProviderUtil.isPQCAvailable()) {
            NoSuchProviderException e = new NoSuchProviderException("No PQC provider available");
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "signMLDSA", e);
            }
            throw e;
        }
        
        String algorithm = privateKey.getAlgorithm();
        String providerName = PQCProviderUtil.getPQCProvider();
        
        Signature sig;
        if (providerName != null) {
            sig = Signature.getInstance(algorithm, providerName);
        } else {
            sig = Signature.getInstance(algorithm);
        }
        
        sig.initSign(privateKey);
        sig.update(data);
        byte[] signature = sig.sign();
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "signMLDSA", "signature length: " + signature.length);
        }
        
        return signature;
    }
    
    /**
     * Verifies an ML-DSA signature.
     * 
     * @param data the data that was signed
     * @param signature the signature to verify
     * @param publicKey the ML-DSA public key
     * @return true if the signature is valid, false otherwise
     * @throws NoSuchAlgorithmException if ML-DSA is not supported
     * @throws NoSuchProviderException if no PQC provider is available
     * @throws InvalidKeyException if the key is invalid
     * @throws SignatureException if verification fails
     */
    @Trivial
    protected static boolean verifyMLDSA(byte[] data, byte[] signature, MLDSAPublicKey publicKey) 
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "verifyMLDSA", "data length: " + data.length + ", signature length: " + signature.length);
        }
        
        if (!PQCProviderUtil.isPQCAvailable()) {
            NoSuchProviderException e = new NoSuchProviderException("No PQC provider available");
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "verifyMLDSA", e);
            }
            throw e;
        }
        
        String algorithm = publicKey.getAlgorithm();
        String providerName = PQCProviderUtil.getPQCProvider();
        
        Signature sig;
        if (providerName != null) {
            sig = Signature.getInstance(algorithm, providerName);
        } else {
            sig = Signature.getInstance(algorithm);
        }
        
        sig.initVerify(publicKey);
        sig.update(data);
        boolean valid = sig.verify(signature);
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "verifyMLDSA", valid);
        }
        
        return valid;
    }
    
    /**
     * Signs data using hybrid mode (RSA + ML-DSA).
     * 
     * <p>In hybrid mode, both RSA and ML-DSA signatures are generated.
     * The token is considered valid only if both signatures verify successfully.
     * 
     * @param data the data to sign
     * @param rsaKey the RSA private key (in LTPA format)
     * @param pqcKey the ML-DSA private key
     * @return a combined signature structure [rsaSig, pqcSig]
     * @throws Exception if signing fails
     */
    @Trivial
    protected static byte[][] signHybrid(byte[] data, byte[][] rsaKey, MLDSAPrivateKey pqcKey) throws Exception {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "signHybrid", "data length: " + data.length);
        }
        
        // 1. Sign with RSA using existing LTPACrypto
        byte[] rsaSignature = LTPACrypto.signISO9796(rsaKey, data, 0, data.length);
        
        // 2. Sign with ML-DSA
        byte[] pqcSignature = signMLDSA(data, pqcKey);
        
        // 3. Combine signatures
        byte[][] result = new byte[][] { rsaSignature, pqcSignature };
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "signHybrid", "RSA sig length: " + rsaSignature.length + 
                                      ", PQC sig length: " + pqcSignature.length);
        }
        
        return result;
    }
    
    /**
     * Verifies a hybrid signature (RSA + ML-DSA).
     * 
     * <p>Both signatures must be valid for the verification to succeed.
     * 
     * @param data the data that was signed
     * @param signatures the combined signature structure [rsaSig, pqcSig]
     * @param rsaKey the RSA public key (in LTPA format)
     * @param pqcKey the ML-DSA public key
     * @return true if both signatures are valid, false otherwise
     * @throws Exception if verification fails
     */
    @Trivial
    protected static boolean verifyHybrid(byte[] data, byte[][] signatures, byte[][] rsaKey, MLDSAPublicKey pqcKey) throws Exception {
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.entry(tc, "verifyHybrid", "data length: " + data.length);
        }
        
        if (signatures == null || signatures.length != 2) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "verifyHybrid", "Invalid signature structure");
            }
            return false;
        }
        
        // 1. Verify RSA signature using existing LTPACrypto
        boolean rsaValid = LTPACrypto.verifyISO9796(rsaKey, data, 0, data.length, 
                                                     signatures[0], 0, signatures[0].length);
        
        if (!rsaValid) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "RSA signature verification failed");
            }
            if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
                Tr.exit(tc, "verifyHybrid", false);
            }
            return false;
        }
        
        // 2. Verify ML-DSA signature
        boolean pqcValid = verifyMLDSA(data, signatures[1], pqcKey);
        
        if (!pqcValid) {
            if (TraceComponent.isAnyTracingEnabled() && tc.isDebugEnabled()) {
                Tr.debug(tc, "ML-DSA signature verification failed");
            }
        }
        
        // 3. Both must be valid
        boolean result = rsaValid && pqcValid;
        
        if (TraceComponent.isAnyTracingEnabled() && tc.isEntryEnabled()) {
            Tr.exit(tc, "verifyHybrid", result);
        }
        
        return result;
    }
    
    /**
     * Gets the algorithm names to try for a given security level.
     * Returns both NIST standard names and alternative names.
     * 
     * @param securityLevel the security level
     * @return array of algorithm names to try
     */
    private static String[] getAlgorithmNames(int securityLevel) {
        switch (securityLevel) {
            case SECURITY_LEVEL_128:
                return new String[] { ML_DSA_44, DILITHIUM2 };
            case SECURITY_LEVEL_192:
                return new String[] { ML_DSA_65, DILITHIUM3 };
            case SECURITY_LEVEL_256:
                return new String[] { ML_DSA_87, DILITHIUM5 };
            default:
                return new String[] { ML_DSA_65, DILITHIUM3 }; // Default to 192-bit
        }
    }
}

// Made with Bob
