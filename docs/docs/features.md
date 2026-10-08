---
hide:
  - navigation
---

# Signum Feature Matrix

This page contains feature matrices, providing a detailed summary of what is and isn't supported.

## Operations

The following table provides an overview about the current status of supported and unsupported cryptographic functionality.
More details about the supported algorithms is provided in the next section.

| Operation                   |          JVM          | Android |       iOS       |
|:----------------------------|:---------------------:|:-------:|:---------------:|
| Signature Creation          |           ✔           |    ✔    |        ✔        |
| Signature Verification      |           ✔           |    ✔    |        ✔        |
| Digest Calculation          |           ✔           |    ✔    |        ✔        |
| Attestation                 |           ❋           |    ✔    |       ✔*        |
| Biometric Auth              |           ✗           |    ✔    |        ✔        |
| Hardware-Backed Key Storage | through dedicated HSM |    ✔    | P-256 keys only |
| Key Agreement               |           ✔           |   ✔†    |        ✔        |
| Asymmetric Encryption       |           ✔           |    ✔    |        ✔        |
| Symmetric Encryption        |           ✔           |    ✔    |        ✔        |
| MAC                         |           ✔           |    ✔    |        ✔        |
| KDF/KSF                     |           ✔           |    ✔    |        ✔        |

Hardware-backed ECDH depends on the platform and device. RSA and symmetric encryption in Supreme use in-memory keys;
the signing provider does not expose hardware-backed encryption APIs.

### ❋ JVM Attestation
The JVM supports a custom attestation format, which can convey attestation
information inside an X.509 certificate.
By default, no semantics are attached to it. It can, therefore be used in any way desired, although this is
highly context-specific.
For example, if a hardware security module is plugged into the JVM crypto provider (e.g. using PKCS11) and this HSM
supports attestation, the JVM-specific attestation format can carry this information. WIP!
If you have suggestions, experience or a concrete use-case where you need this, check the footer and let us know!

### ✔* iOS Attestation
iOS supports App attestation, but no direct key attestation. The Supreme crypto provider emulates key attestation
through app attestation, by _asserting_ the creation of a fresh public/private key pair inside the secure enclave
through application-layer logic encapsulated by the Supreme crypto provider.  
Additional details are described in the [Attestation](supreme.md#attestation) section of the _Supreme_ manual.

### † Android Key Agreement
!!! bug inline end
    The current Supreme Android provider cannot perform key agreement using an auth-on-every-use key.
    **Hence, do not require biometric authentication for keys you want to use for key agreement or
    use a timeout of at least one second!**

Android exposes a `BiometricPrompt.CryptoObject` constructor for `KeyAgreement` starting with
[version 36.1](https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.CryptoObject#CryptoObject(javax.crypto.KeyAgreement)).
Supreme's current key-agreement authentication path does not use that operation-bound prompt.

Key Agreement support in Hardware is spotty on Android: It is only implemented starting with SDK&nbsp;31 (Android&nbsp;12).
Since this is indeed dependent on the crypto hardware (and _KeyMaster_/_KeyMint_ version, etc.), not every device running Android&nbsp;12 or later
will support key agreement in hardware. The reason for this is that devices launched with an earlier version of Android are exempt
from certain (otherwise) hard requirements for Devices launched with later Android versions.
Hence, a device launched with Android&nbsp;10, and later updated to Android&nbsp;12 may still not support key agreement in
hardware.
The Supreme crypto provider throws if key agreement is not supported by the selected hardware-backed key.
<br>
**You can still, however, use key agreement based on software (ephemeral) keys.**

## Supported Algorithms

The following matrix lists the built-in algorithms. Platform and hardware restrictions still apply;
external libraries can contribute additional algorithms through [provider registration](extensibility.md).

| Primitive          | Details                                                                              |
|--------------------|--------------------------------------------------------------------------------------|
| Signature Creation | RSA/ECDSA with SHA2-family hash functions + raw signatures on pre-hashed data        |
| RSA Key Sizes      | 512 (useful for faster tests) up to 4096 (larger keys may not work on all platforms) |
| RSA Padding        | PKCS1 and PSS (with sensible defaults)                                               |
| Elliptic Curves    | NIST Curves (P-256, P-384, P-521)                                                    |
| Digests            | SHA-1 and SHA-2 family (SHA-256, SHA-384, SHA-512)                                   |

On the JVM and on Android, supporting more algorithms is rather easy, since Bouncy Castle works on both platforms
and can be used to provide more algorithms than natively supported. However, we aim for tight platform integration,
especially wrt. hardware-backed key storage and in-hardware computation of cryptographic operations.
We have therefore limited ourselves to what is natively supported on all platforms and most relevant in practice.
External implementations can extend the open algorithm and provider interfaces. See [Extensibility](extensibility.md).

## PKI and Format Integration

Signum provides semantic keys, certificates, and CSRs. Their ASN.1/DER serialization uses
[awesn1](https://a-sit-plus.github.io/awesn1/), which is now its own library.
The standalone parser, builder DSL, primitive types, and OID catalogue are documented there.

| Abstraction | Module | Remarks |
|:------------|:-------|:--------|
| Public and private keys | Indispensable | RSA and NIST EC built-ins; open format providers |
| Certificates and CSRs | Indispensable | Semantic models with source-representation preservation |
| Certificate extensions | Indispensable PKIX | Typed constraints, usages, identifiers and policies; unknown extensions retain their opaque data |
| Distinguished and general names | Indispensable PKIX | Typed attributes and name forms |
| Trust anchors and bundled roots | Indispensable PKIX | Data model and a pinned Apple-sourced root snapshot |
| Path construction and validation | PKIX Supreme | Signatures, validity, constraints, policies and critical extensions |
| Live system trust store | PKIX Supreme | Platform-dependent, best-effort access; see the [PKIX manual](pkix-supreme.md) |
| JOSE | Indispensable Josef | JWK, compact/flattened/general JWS, typed payloads and JWT |
| COSE | Indispensable Cosef | COSE keys, signed messages and CWT |
| HPKE | Supreme | See the [HPKE manual](supreme.md#hybrid-public-key-encryption) for supported suites and modes |

Validation is separate from decoding a certificate. Parsing data successfully does not establish trust.
Refer to [PKIX Supreme](pkix-supreme.md) for explicit trust anchors and validation outcomes.

## Extensibility

Built-in algorithms are defaults, rather than an exhaustive list of what Signum can represent.
External libraries can contribute digests, MACs, KDFs, signing and verification, key formats, platform mappings,
typed certificate data, and configuration DSL options. Those contributions still depend on their own platform support.
See [Extensibility](extensibility.md) for installation and registration requirements.
