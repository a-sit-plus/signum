# PKIX Supreme

This module brings [Supreme](supreme.md)'s cryptographic providers together with
[Indispensable PKIX](indispensable-pkix.md) for certificate path construction and validation.
Use `at.asitplus.signum:pkix-supreme:1.0.0` and opt in to `ExperimentalPkiApi`.

```kotlin
--8<-- "pkix-supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/PkixSupremeExamples.kt:pkix-supreme-opt-in"
```

Install Supreme and PKIX during startup, before the DER/descriptor registries are sealed.

## Construct and Validate a Path

The example uses fixed certificate fixtures and an explicit trust anchor. It does not depend on
the host's trust-store contents or network retrieval:

```kotlin
--8<-- "pkix-supreme/src/jvmTest/kotlin/at/asitplus/signum/examples/PkixSupremeExamples.kt:pkix-supreme-validation"
```

1. The anchor comes from application trust configuration, never merely from the peer's chain.
2. `CertificateChain` is ordered leaf first, followed by intermediates towards the root. The path constructor finds an applicable anchor separately.

`buildPathAndValidate` builds candidate paths and applies the RFC 5280 validator factory.
`Success` includes the end-entity subject and resulting policy tree. `Failure` carries validator
failures for a selected path; `BuildPathFailure` collects failures from candidate paths that did not
validate. `isValid` is true only for `Success`. Structural decoding errors can still throw.

The supplied context controls the validation date, trust anchors, expected extended key usages,
initial policy set and policy flags. Validation covers certificate signatures, validity periods,
CA/basic constraints and path length, key usage and identifiers, name constraints, policy processing
and critical extensions. Built-in name-constraint comparison is implemented for DNS, mail,
URI, directory and IP names. Other name forms may be preserved structurally but do not have
complete built-in narrowing/widening/matching semantics; they can fail constraint processing.
Unknown or unhandled critical extensions fail validation. A custom validator
must explicitly report the extension OIDs it handled. Replacing the validator factory can weaken
these guarantees; a successful custom policy is only as strong as the validators you retained.

This is certification-path validation. It does not implement an online revocation service or fetch
missing certificates, CRLs or OCSP responses for you. The `supportRevocationChecking` context
flag adjusts CRL-signing key-usage checks; it does not perform revocation retrieval or checking. DNS/application identity checks and application
authorization remain the caller's responsibility. Trust anchors are trusted inputs, not ordinary
path certificates; their own certificate validity is not processed as an end-entity validity check.

## System Trust Stores

`systemTrustStore` has type `TrustStore?` and wraps the platform store on a best-effort basis.
It may be incomplete, and is `null` when the platform exposes no accessible store. The common fallback
is `systemTrustStore ?: BundledTrustStore`; the validation context uses that default, so pass explicit
anchors when you need a restricted trust policy. On the JVM, the wrapper uses JSSE's default trust
manager accepted issuers and skips certificates that cannot be converted to Signum values. It complements `BundledTrustStore`, which remains a
pinned cross-platform snapshot. System results depend on OS configuration, user-installed roots,
platform permissions and changes outside the application. The wrappers expose trust anchors for
Signum path processing; they do not reproduce every platform's native trust policy or online behavior.
Use explicit anchors for reproducible tests and restricted application trust policies.

## Certificate Requests and Issuance

A CSR proves possession of its key. It does not prove that a requested name, custom attribute or
attestation claim should be accepted. Validate these claims before issuing a certificate.

!!! tip
    **Do check out the full API docs [here](dokka/pkix-supreme/index.html)** for validator and context options.
