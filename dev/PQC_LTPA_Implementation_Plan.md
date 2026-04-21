# PQC Support for LTPA in Liberty - Implementation Plan

**Issue:** [GitHub #35556](https://github.ibm.com/websphere/WS-CD-Open/issues/35556)  
**Date:** April 21, 2026  
**Feature Size:** 3XL (24-38 person-weeks)

## Executive Summary

This plan outlines the delivery of Post-Quantum Cryptography (PQC) support for LTPA tokens in Open Liberty. The implementation will enable Liberty to use quantum-resistant algorithms (ML-KEM and ML-DSA) for LTPA token generation and validation while maintaining backward compatibility with existing RSA-based tokens.

## Current LTPA Architecture Analysis

### Key Components Identified

1. **LTPAKeyInfoManager** (`com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/LTPAKeyInfoManager.java`)
   - Manages LTPA key loading and creation
   - Handles key file parsing and validation
   - Supports primary and validation keys

2. **LTPAToken2** (`com.ibm.ws.security.token.ltpa/src/com/ibm/ws/security/token/ltpa/internal/LTPAToken2.java`)
   - Token generation and validation
   - RSA signature operations
   - Token encryption/decryption

3. **LTPACrypto** (`com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/LTPACrypto.java`)
   - Core cryptographic operations
   - RSA-1024 (non-FIPS) or RSA-2048 (FIPS)
   - 3DES/AES encryption

4. **LTPADigSignature** (`com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/LTPADigSignature.java`)
   - Digital signature generation
   - RSA key pair generation

### Current Crypto Stack

- **Encryption:** 3DES (non-FIPS) or AES-256-CBC (FIPS 140-3)
- **Signatures:** RSA-1024 (non-FIPS) or RSA-2048 (FIPS) with SHA-256
- **Key Format:** Custom LTPA key file format with version 1.0 (non-FIPS) or 2.0 (FIPS)

## Implementation Strategy

### Phase 1: Foundation & Design (Weeks 1-3)
**Size:** M (4-5 person-weeks)

#### 1.1 Research & Standards Analysis

- Study NIST PQC standards:
  - FIPS 203: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
  - FIPS 204: ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
- Analyze Java provider support:
  - IBM Semeru OpenJCEPlus (ML-KEM, ML-DSA) - Available July 2025
  - IBM Java 8 IBMJCEPlus - Available July 2025
  - z/OS IBMJCECCA provider - Available June 2025
  - OpenJDK 24+ SunJCE provider - Available March 2025
- Document algorithm parameters and key sizes:
  - ML-DSA-65: 2.5KB signatures, 128-bit security
  - ML-DSA-87: 4KB signatures, 192-bit security
  - ML-KEM-768: 128-bit security for key encapsulation

#### 1.2 Design Hybrid Crypto Approach

**Three Operating Modes:**

1. **Hybrid Mode (Recommended):** PQC + Classical
   - Dual signatures: RSA + ML-DSA
   - Both signatures must verify successfully
   - Provides quantum resistance while maintaining classical security

2. **Pure PQC Mode:** ML-DSA only
   - Future-ready for post-quantum era
   - Smaller token size than hybrid

3. **Legacy Mode:** RSA only (existing behavior)
   - Backward compatibility
   - No PQC overhead

**Key Encapsulation:**
- Use ML-KEM for protecting shared keys
- Hybrid approach: ML-KEM + RSA key wrapping

#### 1.3 LTPA Key File Format Extension

**Proposed Version 3.0 Format:**

```properties
# IBM WebSphere Application Server key file
# PQC-enabled LTPA keys
com.ibm.websphere.ltpa.version=3.0
com.ibm.websphere.ltpa.Realm=SecureRealm
com.ibm.websphere.CreationDate=...
com.ibm.websphere.CreationHost=...

# Classical keys (for hybrid mode)
com.ibm.websphere.ltpa.3DESKey=...
com.ibm.websphere.ltpa.PrivateKey=...
com.ibm.websphere.ltpa.PublicKey=...

# PQC configuration
com.ibm.websphere.ltpa.pqc.algorithm=ML-DSA-65
com.ibm.websphere.ltpa.pqc.mode=hybrid
com.ibm.websphere.ltpa.pqc.PrivateKey=<base64-encoded>
com.ibm.websphere.ltpa.pqc.PublicKey=<base64-encoded>

# Key encapsulation
com.ibm.websphere.ltpa.kem.algorithm=ML-KEM-768
com.ibm.websphere.ltpa.kem.PublicKey=<base64-encoded>
com.ibm.websphere.ltpa.kem.PrivateKey=<base64-encoded>
```

### Phase 2: Core Implementation (Weeks 4-8)
**Size:** XL (10-15 person-weeks)

#### 2.1 Extend Crypto Layer

**Files to Modify:**

**LTPACrypto.java:**
```java
// New methods to add:
protected static byte[] signML_DSA(byte[] data, MLDSAPrivateKey privKey) throws Exception
protected static boolean verifyML_DSA(byte[] data, byte[] signature, MLDSAPublicKey pubKey) throws Exception
protected static byte[] encryptML_KEM(byte[] data, MLKEMPublicKey pubKey) throws Exception
protected static byte[] decryptML_KEM(byte[] encData, MLKEMPrivateKey privKey) throws Exception

// Hybrid signature support
protected static byte[] signHybrid(byte[] data, LTPAPrivateKey rsaKey, MLDSAPrivateKey pqcKey) throws Exception
protected static boolean verifyHybrid(byte[] data, byte[] rsaSig, byte[] pqcSig, 
                                     LTPAPublicKey rsaKey, MLDSAPublicKey pqcKey) throws Exception
```

**LTPADigSignature.java:**
```java
// New key generation methods
static MLDSAKeyPair generateMLDSAKeyPair(int securityLevel)
static MLKEMKeyPair generateMLKEMKeyPair(int securityLevel)
static LTPAKeyPairV3 generateHybridKeyPair()
```

#### 2.2 Update Token Layer

**LTPAToken2.java modifications:**

```java
public class LTPAToken2 implements Token, Serializable {
    // Add PQC fields
    private byte[] pqcSignature;
    private final MLDSAPrivateKey pqcPrivateKey;
    private final MLDSAPublicKey pqcPublicKey;
    private PQCMode pqcMode; // DISABLED, HYBRID, PURE
    
    // Update sign() method for hybrid signatures
    private void sign() throws Exception {
        // Generate RSA signature (existing)
        byte[] rsaSignature = signRSA(data, this.privateKey);
        
        // Generate PQC signature if enabled
        if (pqcMode != PQCMode.DISABLED) {
            this.pqcSignature = signML_DSA(data, this.pqcPrivateKey);
        }
        
        this.setSignature(rsaSignature);
    }
    
    // Update verify() method for hybrid verification
    private boolean verify() throws Exception {
        boolean rsaVerified = verifyRSA(data, signature, publicKey);
        
        if (pqcMode == PQCMode.HYBRID) {
            boolean pqcVerified = verifyML_DSA(data, pqcSignature, pqcPublicKey);
            return rsaVerified && pqcVerified; // Both must pass
        } else if (pqcMode == PQCMode.PURE) {
            return verifyML_DSA(data, pqcSignature, pqcPublicKey);
        }
        
        return rsaVerified; // Legacy mode
    }
}
```

#### 2.3 Key Management Updates

**LTPAKeyInfoManager.java:**
- Add methods to load PQC keys from v3.0 key files
- Handle key migration from v1.0/2.0 to v3.0
- Support validation keys with PQC
- Detect and handle missing PQC providers gracefully

**LTPAKeyFileCreatorImpl.java:**
- Generate PQC key pairs (ML-DSA, ML-KEM)
- Create v3.0 format key files
- Support key generation for all three modes

#### 2.4 Configuration Support

**New server.xml Configuration:**

```xml
<ltpa keysFileName="ltpa.keys" 
      keysPassword="{xor}..." 
      expiration="120"
      pqcEnabled="true"
      pqcMode="hybrid"
      pqcAlgorithm="ML-DSA-65"
      kemAlgorithm="ML-KEM-768"/>
```

**Configuration Properties:**
- `pqcEnabled`: Enable/disable PQC support (default: false)
- `pqcMode`: "hybrid", "pure", or "disabled"
- `pqcAlgorithm`: "ML-DSA-65" or "ML-DSA-87"
- `kemAlgorithm`: "ML-KEM-768" or "ML-KEM-1024"

### Phase 3: Testing & Validation (Weeks 9-11)
**Size:** L (6-9 person-weeks)

#### 3.1 Create FAT Tests

**New Test Project:** `com.ibm.ws.security.token.ltpa.pqc_fat`

**Test Coverage:**
1. PQC key generation and storage
2. Hybrid token creation and validation
3. Pure PQC token creation and validation
4. Backward compatibility (v1.0/2.0 tokens on v3.0 server)
5. Forward compatibility (v3.0 tokens rejected by v1.0/2.0 servers)
6. Key rotation with PQC
7. Validation keys with PQC
8. Cross-version interoperability
9. Provider availability detection and fallback
10. Configuration validation
11. Error handling and recovery

**Test Scenarios:**
```java
@Test
public void testHybridTokenCreationAndValidation()
@Test
public void testPurePQCTokenCreationAndValidation()
@Test
public void testBackwardCompatibility_V2TokenOnV3Server()
@Test
public void testKeyRotation_RSAToHybrid()
@Test
public void testProviderNotAvailable_GracefulFallback()
@Test
public void testTokenSizeIncrease_HybridVsRSA()
@Test
public void testCrossServerValidation_HybridTokens()
```

#### 3.2 Performance Testing

**Metrics to Measure:**
- Token generation time: RSA vs Hybrid vs Pure PQC
- Token validation time: RSA vs Hybrid vs Pure PQC
- Token size: RSA (~512 bytes) vs Hybrid (~3KB) vs Pure PQC (~2.5KB)
- Throughput impact: Requests/second with PQC enabled
- Memory usage: Heap impact of PQC operations
- CPU utilization: Processing overhead

**Performance Targets:**
- Token generation: < 20% slower than RSA
- Token validation: < 20% slower than RSA
- Throughput: > 80% of RSA baseline
- Memory: < 10% increase in heap usage

#### 3.3 Security Validation

**Security Testing:**
1. Cryptographic correctness verification
2. FIPS 140-3 compliance testing
3. Side-channel attack resistance
4. Key strength validation
5. Signature verification robustness
6. Token tampering detection
7. Replay attack prevention

**Security Review Checklist:**
- [ ] Algorithm implementation reviewed by crypto experts
- [ ] Key generation uses secure random sources
- [ ] No key material leakage in logs or traces
- [ ] Proper key lifecycle management
- [ ] Secure key storage and transmission
- [ ] Compliance with NIST PQC standards

### Phase 4: Documentation & Release (Weeks 12-14)
**Size:** M (4-5 person-weeks)

#### 4.1 Create UFO Document

**UFO Contents:**
1. Executive Summary
2. Architecture diagrams
3. Algorithm selection rationale
4. Migration strategy
5. Performance characteristics
6. Security considerations
7. Compatibility matrix
8. Configuration examples
9. Troubleshooting guide

#### 4.2 Documentation Updates

**Documentation Deliverables:**

1. **Configuration Guide:**
   - How to enable PQC support
   - Configuration options explained
   - Mode selection guidance
   - Provider requirements

2. **Migration Guide:**
   - Migrating from RSA to Hybrid
   - Key rotation procedures
   - Rollback procedures
   - Testing migration in staging

3. **Troubleshooting Guide:**
   - Common issues and solutions
   - Provider detection failures
   - Performance tuning
   - Debugging PQC issues

4. **Security Best Practices:**
   - When to use hybrid vs pure PQC
   - Key rotation recommendations
   - Monitoring and auditing
   - Compliance considerations

#### 4.3 Serviceability

**Trace Points:**
```java
// Add trace for PQC operations
if (tc.isDebugEnabled()) {
    Tr.debug(tc, "Generating PQC signature using " + pqcAlgorithm);
}
```

**Error Messages:**
- `LTPA_PQC_PROVIDER_NOT_AVAILABLE`: PQC provider not found, falling back to RSA
- `LTPA_PQC_KEY_GENERATION_FAILED`: Failed to generate PQC keys
- `LTPA_PQC_SIGNATURE_VERIFICATION_FAILED`: PQC signature verification failed
- `LTPA_PQC_INVALID_CONFIGURATION`: Invalid PQC configuration detected

**FFDC:**
- Capture crypto exceptions with context
- Log provider information
- Include configuration details
- Sanitize sensitive key material

**Performance Monitoring:**
- Add PMI metrics for PQC operations
- Track token generation/validation times
- Monitor token size distribution
- Alert on performance degradation

## Key Technical Decisions

### 1. Hybrid Crypto Approach (Recommended)

**Rationale:**
- Provides quantum resistance while maintaining classical security
- Protects against "harvest now, decrypt later" attacks
- Allows gradual transition to pure PQC
- Industry best practice during transition period

**Implementation:**
- Dual signatures (RSA + ML-DSA) in token
- Both signatures must verify successfully
- Slightly larger token size (~3KB vs ~512 bytes)

### 2. Algorithm Selection

**ML-DSA-65 (Default):**
- 2.5KB signatures
- 128-bit security level
- Good balance of security and performance
- Suitable for most deployments

**ML-DSA-87 (High Security):**
- 4KB signatures
- 192-bit security level
- For high-security environments
- Larger token size impact

**ML-KEM-768 (Key Encapsulation):**
- 128-bit security level
- Protects shared keys
- Minimal performance impact

### 3. Backward Compatibility Strategy

**Compatibility Matrix:**

| Server Version | v1.0 Token | v2.0 Token | v3.0 Token |
|----------------|------------|------------|------------|
| v1.0 Server    | ✅ Valid   | ❌ Invalid | ❌ Invalid |
| v2.0 Server    | ✅ Valid   | ✅ Valid   | ❌ Invalid |
| v3.0 Server    | ✅ Valid   | ✅ Valid   | ✅ Valid   |

**Migration Path:**
1. Upgrade all servers to v3.0 (PQC disabled)
2. Enable PQC on one server (hybrid mode)
3. Test token validation across servers
4. Gradually enable PQC on remaining servers
5. Use validation keys for smooth transition

### 4. Provider Detection

**Provider Detection Logic:**

```java
public static boolean isPQCAvailable() {
    try {
        // Check for IBM Semeru OpenJCEPlus
        if (Security.getProvider("OpenJCEPlus") != null) {
            return checkMLDSASupport("OpenJCEPlus");
        }
        
        // Check for IBM Java IBMJCEPlus
        if (Security.getProvider("IBMJCEPlus") != null) {
            return checkMLDSASupport("IBMJCEPlus");
        }
        
        // Check for z/OS IBMJCECCA
        if (Security.getProvider("IBMJCECCA") != null) {
            return checkMLDSASupport("IBMJCECCA");
        }
        
        // Check for OpenJDK 24+ SunJCE
        if (Security.getProvider("SunJCE") != null) {
            return checkMLDSASupport("SunJCE");
        }
        
        return false;
    } catch (Exception e) {
        Tr.warning(tc, "PQC_PROVIDER_CHECK_FAILED", e.getMessage());
        return false;
    }
}

private static boolean checkMLDSASupport(String provider) {
    try {
        Signature.getInstance("ML-DSA-65", provider);
        return true;
    } catch (NoSuchAlgorithmException e) {
        return false;
    }
}
```

## Dependencies & Prerequisites

### Java Runtime Requirements

**IBM Semeru 17+:**
- OpenJCEPlus provider
- Distributed platforms (except Mac x86)
- Available since July 2025

**IBM Java 8:**
- IBMJCEPlus provider
- Distributed platforms
- Available since July 2025

**z/OS:**
- IBMJCECCA provider
- IBM Semeru 17+
- Available since June 2025

**OpenJDK 24+:**
- SunJCE provider
- All platforms
- Available since March 2025

### Build System Updates

**Maven Dependencies:**
- Update `cnf/oss_dependencies.maven` for any new crypto libraries
- Ensure alphabetical ordering
- Verify FIPS 140-3 compliance maintained

**Gradle Configuration:**
- No changes to build system required
- PQC support is runtime-detected
- Graceful degradation if providers unavailable

## Risk Mitigation

### Technical Risks

1. **Provider Availability**
   - **Risk:** PQC provider not available at runtime
   - **Mitigation:** Implement graceful degradation to RSA
   - **Detection:** Provider check at startup with warning messages

2. **Performance Impact**
   - **Risk:** PQC operations significantly slower than RSA
   - **Mitigation:** Make PQC optional, default to disabled initially
   - **Monitoring:** Add performance metrics and alerts

3. **Token Size**
   - **Risk:** Larger tokens impact network/storage
   - **Mitigation:** Document size increase, test with large deployments
   - **Optimization:** Consider token compression

4. **Interoperability**
   - **Risk:** Cross-version token validation issues
   - **Mitigation:** Extensive cross-version testing
   - **Validation:** Compatibility matrix testing

### Process Risks

1. **Standards Evolution**
   - **Risk:** NIST PQC standards may change
   - **Mitigation:** Design for flexibility, monitor NIST updates
   - **Strategy:** Use provider abstraction layer

2. **Timeline**
   - **Risk:** Implementation takes longer than estimated
   - **Mitigation:** Phased delivery allows early feedback
   - **Contingency:** Can deliver hybrid mode first, pure PQC later

3. **Testing Complexity**
   - **Risk:** Insufficient test coverage
   - **Mitigation:** Automated FAT suite with multiple configurations
   - **Coverage:** Aim for >90% code coverage

## Success Criteria

1. ✅ PQC key generation and storage working
2. ✅ Hybrid token creation/validation functional
3. ✅ Backward compatibility maintained (v1.0/2.0 tokens work on v3.0 servers)
4. ✅ Performance within 20% of RSA baseline
5. ✅ All FAT tests passing (>95% pass rate)
6. ✅ Documentation complete and reviewed
7. ✅ UFO approved by Chief Architect
8. ✅ Security review passed
9. ✅ FIPS 140-3 compliance maintained
10. ✅ Provider detection and fallback working

## Timeline Summary

**Total Effort:** 24-38 person-weeks (3XL feature)

**Calendar Time:** 14 weeks with 2-3 developers

**Phase Breakdown:**
- Phase 1 (Design): 3 weeks
- Phase 2 (Implementation): 5 weeks
- Phase 3 (Testing): 3 weeks
- Phase 4 (Documentation): 3 weeks

**Target Release:** TBD based on prioritization

## Next Steps

1. **Immediate Actions:**
   - Schedule UFO review with Chief Architect
   - Obtain prioritization approval from Product Management
   - Assign development team (2-3 developers)
   - Set up development environment with PQC providers

2. **Phase 1 Kickoff:**
   - Begin research on NIST PQC standards
   - Analyze Java provider capabilities
   - Create detailed design document
   - Prototype PQC key generation

3. **Stakeholder Communication:**
   - Present plan to Security team
   - Review with Performance team
   - Coordinate with Documentation team
   - Align with Release Management

4. **Infrastructure Setup:**
   - Create feature branch
   - Set up CI/CD pipeline
   - Configure test environments
   - Install PQC providers on test systems

## Appendix

### A. Glossary

- **PQC:** Post-Quantum Cryptography
- **ML-KEM:** Module-Lattice-Based Key-Encapsulation Mechanism (FIPS 203)
- **ML-DSA:** Module-Lattice-Based Digital Signature Algorithm (FIPS 204)
- **LTPA:** Lightweight Third-Party Authentication
- **FAT:** Feature Acceptance Test
- **UFO:** Upcoming Feature Overview
- **FIPS:** Federal Information Processing Standards

### B. References

- NIST PQC Standards: https://csrc.nist.gov/projects/post-quantum-cryptography
- FIPS 203 (ML-KEM): https://doi.org/10.6028/NIST.FIPS.203
- FIPS 204 (ML-DSA): https://doi.org/10.6028/NIST.FIPS.204
- GitHub Issue #35556: https://github.ibm.com/websphere/WS-CD-Open/issues/35556

### C. Contact Information

- **Feature Owner:** TBD
- **Chief Architect:** OpenLiberty/chief-architect team
- **Security Focal:** websphere/security-approvers team
- **Performance Focal:** websphere/performance-approvers team

---

**Document Version:** 1.0  
**Last Updated:** April 21, 2026  
**Status:** Draft - Awaiting Approval