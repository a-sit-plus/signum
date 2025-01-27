---
hide:
  - navigation
---

# Signum Feature Matrix

This page contains feature matrices, providing a detailed summary of what is and isn't supported.

## Operations

The following table provides an overview about the current status of supported and unsupported cryptographic
functionality.
More details about the supported algorithms is provided in the next section.

| Operation                   |          JVM          | Android |       iOS       |
|:----------------------------|:---------------------:|:-------:|:---------------:|
| ASN.1 Encoding + Decoding   |           ✔           |    ✔    |        ✔        |
| Signature Creation          |           ✔           |    ✔    |        ✔        |
| Signature Verification      |           ✔           |    ✔    |        ✔        |
| Digest Calculation          |           ✔           |    ✔    |        ✔        |
| Attestation                 |           ❋           |    ✔    |       ✔*        |
| Biometric Auth              |           ✗           |    ✔    |        ✔        |
| Hardware-Backed Key Storage | through dedicated HSM |    ✔    | P-256 keys only |
| Key Agreement               |           ✔           |   ✔†    |        ✔        |
| Asymmetric Encryption       |           ✗           |    ✗    |        ✗        |
| Symmetric Encryption        |           ✔           |    ✔    |        ✔        |
| MAC                         |           ✔           |    ✔    |        ✔        |

Hardware-backed key agreement, asymmetric and symmetric encryption are WIP and will be supported in an upcoming release.
This is more than a mere lip service, since we (A-SIT Plus GmbH) need this functionality urgently ourselves and are
already working on it.

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
    All Android versions supporting key agreement contain a bug, which makes it impossible
    to perform key agreement using an auth-on-every-use key. The bugfix is hidden behind a disabled-by-default
    feature flag in the Android source code.
    **Hence, do not require biometric authentication for keys you want to use for key agreement or
    use a timeout of at leas one second!**

Key Agreement support in Hardware is spotty on Android: It is only implemented starting with SDK&nbsp;31 (Android&nbsp;12).
Since this is indeed dependent on the crypto hardware (and _KeyMaster_/_KeyMint_ version, etc.), not every device running Android&nbsp;12 or later
will support key agreement in hardware. The reason for this is that devices launched with an earlier version of Android are exempt
from certain (otherwise) hard requirements for Devices launched with later Android versions.
Hence, a device launched with Android&nbsp;10, and later updated to Android&nbsp;12 may still not support key agreement in
hardware.
The Supreme crypto provider will return a failure, in if key agreement is not supported in hardware.
<br>
**You can still, however, use key agreement based on software (ephemeral) keys.**

## Supported Algorithms

The following matrix lists all supported algorithms and details.
Since everything is supported on all platforms equally,
a separate platform listing is omitted.

| Primitive            | Details                                                                                           |
|----------------------|---------------------------------------------------------------------------------------------------|
| Signature Creation   | RSA/ECDSA with SHA2-family hash functions + raw signatures on pre-hashed data                     |
| RSA Key Sizes        | 512 (useful for faster tests) up to 4096 (larger keys may not work on all platforms)              |
| RSA Padding          | PKCS1 and PSS (with sensible defaults)                                                            |
| Elliptic Curves      | NIST Curves (P-256, P-384, P-521)                                                                 |
| Digests              | SHA-1 and SHA-2 family (SHA-256, SHA-384, SHA-512)                                                |
| MAC                  | HMAC based on the SHA-1 and SHA-2 family (SHA-256, SHA-384, SHA-512)                              |
| Symmetric Encryption | ChaCha-Poly1503, AES-GCM, AES-CBC-HMAC, AES KW (RFC RFC3394),  AES-CBC (Unauthenticated), AES-ECB |

On the JVM and on Android, supporting more algorithms is rather easy, since Bouncy Castle works on both platforms
and can be used to provide more algorithms than natively supported. However, we aim for tight platform integration,
especially wrt. hardware-backed key storage and in-hardware computation of cryptographic operations.
We have therefore limited ourselves to what is natively supported on all platforms and most relevant in practice.
Different block cipher modes of operation can be added on request.

## High-Level ASN.1 Abstractions

The `indispensable-asn1` module comes with a fully-featured ASN.1 engine including a builder DSL.
In addition to low-level, generic abstractions, it also provides higher-level datatypes with enriched
semantics. The `indispensable` module builds on top of it, adding cryptography-specific data types.
Combined these two modules provide the following abstractions:

| Abstraction                  |   | Remarks                                                                                                                                                                              |
|------------------------------|:-:|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| X.509 Certificate            | ❋ | Only supported algorithms can be parsed as certificate.<br> Certificates containing other algorithm can be parsed as generic ASN.1 structure. Parser is too lenient in some aspects. |
| X.509 Certificate Extension  | ❋ | Almost no predefined extensions. Need to be manually created.                                                                                                                        |
| Relative Distinguished Names | ❋ | Rather barebones with little to no validation.                                                                                                                                       |
| Alternative Names            | ❋ | Only basic structural validation.                                                                                                                                                    |
| PKCS10 CSR                   | ❋ | Almost certainly a bit too lenient.                                                                                                                                                  |
| PKCS10 CSR Attributes        | ❋ | No predefined attributes. Need to be manually created.                                                                                                                               |
| X.509 Signature Algorithm    | ❋ | Only supported algorithms.                                                                                                                                                           |
| Public Keys                  | ❋ | Only supported types.                                                                                                                                                                |
| Private Keys                 | ❋ | Only supported types.                                                                                                                                                                |
| ASN.1 Integer                |   | Supports `Int`, `UInt`, `Long`, `ULong`, and `BigInteger` and custom varint `Asn1Integer`.                                                                                           |
| ASN.1 Time                   |   | Maps from/to kotlinx-datetime `Instant`. Automatic choice of `GENERALIZED` and  `UTC` time.                                                                                          |
| ASN.1 String                 |   | All types supported, with little to no validation, however.                                                                                                                          |
| ASN.1 Object Identifier      |   | Only `1` and `2` subtrees supported. `KnownOIDs` is generated from _dumpasn1_.                                                                                                       |
| ASN.1 Octet String           |   | Primitive octet strings and encapsulating complex structures natively supported for encoding and parsing.                                                                            |
| ASN.1 Bit String             |   | Relies on custom `BitSet` implementation, but also supports encoding raw bytes.                                                                                                      |

!!! info
❋ marks abstractions added by the `indispensable` module