# PQC LTPA Implementation Status

**Branch:** `feature/pqc-ltpa-support`  
**Created:** April 21, 2026  
**Status:** Skeleton Structure Created

## Overview

This document tracks the implementation status of Post-Quantum Cryptography (PQC) support for LTPA tokens in Open Liberty. The implementation follows the plan outlined in `PQC_LTPA_Implementation_Plan.md`.

## Current Status: Phase 1 - Skeleton Structure ✅

### Completed Files

#### 1. Core PQC Classes (com.ibm.ws.crypto.ltpakeyutil)

- ✅ **PQCMode.java** - Enum defining PQC operating modes (DISABLED, HYBRID, PURE)
- ✅ **MLDSAPrivateKey.java** - ML-DSA private key representation
- ✅ **MLDSAPublicKey.java** - ML-DSA public key representation
- ✅ **MLDSAKeyPair.java** - ML-DSA key pair container
- ✅ **PQCProviderUtil.java** - Provider detection and management utility
- ✅ **LTPACryptoPQC.java** - PQC cryptographic operations (stub methods)

### File Structure

```
com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/
├── PQCMode.java                 (82 lines) - COMPLETE
├── MLDSAPrivateKey.java         (95 lines) - COMPLETE
├── MLDSAPublicKey.java          (95 lines) - COMPLETE
├── MLDSAKeyPair.java            (73 lines) - COMPLETE
├── PQCProviderUtil.java         (189 lines) - COMPLETE
└── LTPACryptoPQC.java           (207 lines) - STUB METHODS
```

## Next Steps

### Phase 1 Remaining Tasks

1. **Configuration Classes** (TODO)
   - [ ] Create `LTPAConfigurationPQC.java` for PQC-specific configuration
   - [ ] Add PQC properties to existing configuration classes
   - [ ] Create configuration validation logic

2. **Token Layer Stubs** (TODO)
   - [ ] Extend `LTPAToken2.java` with PQC fields and methods
   - [ ] Create `LTPAToken3.java` for v3.0 token format
   - [ ] Add hybrid signature support

3. **Key Management Stubs** (TODO)
   - [ ] Extend `LTPAKeyInfoManager.java` for v3.0 key files
   - [ ] Create `LTPAKeyFileCreatorV3.java` for PQC key generation
   - [ ] Add key migration logic

4. **Documentation** (TODO)
   - [ ] Create API documentation for new classes
   - [ ] Document PQC mode selection guidelines
   - [ ] Create migration guide

### Phase 2: Implementation (Not Started)

All methods in `LTPACryptoPQC.java` are currently stubs with TODO comments. Implementation requires:

1. **PQC Provider Integration**
   - Actual ML-DSA key generation
   - Signature generation and verification
   - Provider-specific handling

2. **Key File Format**
   - Define v3.0 LTPA key file format
   - Implement serialization/deserialization
   - Add backward compatibility

3. **Token Format**
   - Define hybrid token structure
   - Implement token encryption with PQC
   - Add signature embedding

### Phase 3: Testing (Not Started)

- [ ] Unit tests for all PQC classes
- [ ] FAT tests for token generation/validation
- [ ] Cross-version compatibility tests
- [ ] Performance benchmarks

### Phase 4: Documentation (Not Started)

- [ ] UFO document
- [ ] Configuration guide
- [ ] Migration guide
- [ ] Troubleshooting guide

## Implementation Notes

### Design Decisions

1. **Hybrid Mode as Default**
   - Provides quantum resistance while maintaining classical security
   - Both RSA and ML-DSA signatures must verify
   - Recommended for production during transition period

2. **Provider Abstraction**
   - `PQCProviderUtil` handles provider detection
   - Supports multiple providers (OpenJCEPlus, IBMJCEPlus, IBMJCECCA, SunJCE)
   - Graceful fallback to RSA-only mode if PQC unavailable

3. **Backward Compatibility**
   - v3.0 servers can validate v1.0/2.0 tokens
   - v1.0/2.0 servers reject v3.0 tokens
   - Validation keys support mixed environments

### Key Classes and Their Roles

| Class | Purpose | Status |
|-------|---------|--------|
| `PQCMode` | Defines operating modes | Complete |
| `MLDSAPrivateKey` | PQC private key | Complete |
| `MLDSAPublicKey` | PQC public key | Complete |
| `MLDSAKeyPair` | Key pair container | Complete |
| `PQCProviderUtil` | Provider detection | Complete |
| `LTPACryptoPQC` | Crypto operations | Stub methods |

### TODO Comments Summary

The following methods have TODO comments indicating required implementation:

#### LTPACryptoPQC.java
- `generateMLDSAKeyPair()` - Generate ML-DSA key pairs
- `signMLDSA()` - Sign data with ML-DSA
- `verifyMLDSA()` - Verify ML-DSA signatures
- `signHybrid()` - Hybrid RSA + ML-DSA signing
- `verifyHybrid()` - Hybrid signature verification

#### MLDSAPrivateKey.java
- `getEncoded()` - Implement key encoding for v3.0 format

#### MLDSAPublicKey.java
- `getEncoded()` - Implement key encoding for v3.0 format

#### PQCProviderUtil.java
- `detectPQCProvider()` - Currently returns null, needs actual detection

## Testing Strategy

### Unit Tests (Not Created)
- Test PQC mode enum operations
- Test key class constructors and getters
- Test provider detection logic
- Mock PQC operations for testing

### Integration Tests (Not Created)
- Test key generation with actual providers
- Test signature generation and verification
- Test hybrid mode operations
- Test provider fallback scenarios

### FAT Tests (Not Created)
- End-to-end token creation and validation
- Cross-server token validation
- Key rotation scenarios
- Performance benchmarks

## Dependencies

### Required for Implementation
- PQC cryptographic provider (one of):
  - OpenJCEPlus (IBM Semeru 17+)
  - IBMJCEPlus (IBM Java 8)
  - IBMJCECCA (z/OS)
  - SunJCE (OpenJDK 24+)

### Build Dependencies
- No new Maven dependencies required
- Uses existing Liberty build infrastructure
- Gradle build system unchanged

## Git Status

```bash
# Current branch
git branch
* feature/pqc-ltpa-support

# New files
git status --short
A  PQC_LTPA_Implementation_Plan.md
A  PQC_IMPLEMENTATION_STATUS.md
A  com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/PQCMode.java
A  com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/MLDSAPrivateKey.java
A  com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/MLDSAPublicKey.java
A  com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/MLDSAKeyPair.java
A  com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/PQCProviderUtil.java
A  com.ibm.ws.crypto.ltpakeyutil/src/com/ibm/ws/crypto/ltpakeyutil/LTPACryptoPQC.java
```

## How to Continue Implementation

### For Developers

1. **Review the Plan**
   - Read `PQC_LTPA_Implementation_Plan.md` for full context
   - Understand the hybrid crypto approach
   - Review NIST PQC standards (FIPS 203, FIPS 204)

2. **Set Up Environment**
   - Install a PQC-capable Java runtime
   - Verify provider availability with `PQCProviderUtil`
   - Run existing LTPA tests to establish baseline

3. **Implement Core Methods**
   - Start with `LTPACryptoPQC.generateMLDSAKeyPair()`
   - Implement signing and verification
   - Add comprehensive error handling

4. **Extend Existing Classes**
   - Modify `LTPAToken2` to support PQC fields
   - Update `LTPAKeyInfoManager` for v3.0 keys
   - Add configuration support

5. **Write Tests**
   - Create unit tests for each new class
   - Add FAT tests for end-to-end scenarios
   - Benchmark performance impact

### For Code Review

When reviewing this skeleton:
- ✅ Class structure and naming conventions
- ✅ Package organization
- ✅ Documentation and comments
- ✅ TODO markers for implementation
- ⚠️ No actual cryptographic implementation yet
- ⚠️ All crypto methods throw UnsupportedOperationException

## References

- **Implementation Plan:** `PQC_LTPA_Implementation_Plan.md`
- **GitHub Issue:** https://github.ibm.com/websphere/WS-CD-Open/issues/35556
- **NIST PQC Project:** https://csrc.nist.gov/projects/post-quantum-cryptography
- **FIPS 203 (ML-KEM):** https://doi.org/10.6028/NIST.FIPS.203
- **FIPS 204 (ML-DSA):** https://doi.org/10.6028/NIST.FIPS.204

## Contact

For questions about this implementation:
- Feature Owner: TBD
- Security Team: websphere/security-approvers
- Architecture Team: OpenLiberty/chief-architect

---

**Last Updated:** April 21, 2026  
**Next Review:** After Phase 1 completion