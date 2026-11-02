# **PKIX** X.509 Parsing &amp; Path Validation

The PKIX modules give you typed X.509 data structures and RFC 5280-compliant certificate path validation for Kotlin Multiplatform.

* **Indispensable PKIX** (indispensable-pkix) parses certificates, CRLs, and CSR data into typed, immutable Kotlin models &rarr; no reflection, no stringly-typed extension handling
* **Signum Supreme PKIX** (pkix-supreme) builds certification paths and validates them against RFC 5280 section 6.1: policy processing, name constraints, basic constraints, key usage, chain integrity, and time validity

!!! tip
    **Do check out the full API docs [here](dokka/pkix-supreme/index.html)!**

## Using it in your Projects

Both modules are Kotlin Multiplatform and target the JVM, Android, and iOS.

```kotlin
implementation("at.asitplus.signum:indispensable-pkix:$version")
implementation("at.asitplus.signum:pkix-supreme:$version")
```

!!! warning
    The PKIX API is still experimental. All public entry points require opting in with `@OptIn(ExperimentalPkiApi::class)`.

## Validating a Chain

The simplest way to validate a certificate chain is to build the path against a set of trust anchors and run the default RFC 5280 validator pipeline:

```kotlin
@OptIn(ExperimentalPkiApi::class)
val result = chain.buildPathAndValidate(
    CertificateValidationContext(
        date = validationDate,
        trustAnchors = trustStore,
    )
)
```

`buildPathAndValidate` returns a sealed `CertificateValidationResult`:

* `Success` &mdash; a valid certification path was found, carrying the resolved policy node and the end-entity certificate
* `Failure` &mdash; the chain was anchored but one or more validators failed; every failure names its validator and the underlying cause
* `BuildPathFailure` &mdash; no candidate chain could be anchored; failures are collected per attempted chain

If you already have an anchored chain, call `AnchoredCertificateChain.validate` directly. Both entry points accept a custom `ValidatorFactory` when you need a non-RFC pipeline.

### Configuration Knobs

`CertificateValidationContext` controls validation behaviour:

* `date` &mdash; the validation time (defaults to the system clock)
* `initialPolicies` / `explicitPolicyRequired` &mdash; certificate policy processing
* `policyMappingInhibited`, `anyPolicyInhibited`, `policyQualifiersRejected` &mdash; policy flags from the PKIX profile
* `expectedEku` &mdash; extended key usages the leaf must carry
* `leafKeyUsageCheck` &mdash; a lambda that defines how leaf key usage is handled
* `supportRevocationChecking` &mdash; require CRL signing capability on CA certificates
* `allowIncludedTrustAnchor` &mdash; whether a trust anchor certificate may already be part of the submitted chain
* `trustAnchors` &mdash; the anchor set (defaults to the system trust store, falling back to the bundled one)

## Trust Anchors

A trust anchor may be specified as a certificate or as a bare public key. Certificate-backed anchors are subject to the same CA conformance checks as any certificate in the path (basicConstraints present, critical, cA=true; keyCertSign key usage; SKI/AKI presence and criticality). Public-key anchors establish trust by issuer-name match and signature verification alone. To accept legacy roots without a basicConstraints extension, specify them as public-key anchors.

## Supported Validators

The default RFC 5280 pipeline runs these validators:

| Validator | Checks |
|---|---|
| `PolicyValidator` | certificate policy processing, incl. explicit-policy and policy-mapping rules |
| `CertValidityValidator` | certificate is structurally sound despite lenient decoding |
| `NameConstraintsValidator` | RFC 5280 4.2.1.10 name constraints |
| `KeyUsageValidator` | key usage / extended key usage conformance |
| `BasicConstraintsValidator` | CA status, path length constraint, criticality |
| `ChainValidator` | signature integrity and issuer/subject name matching |
| `TimeValidityValidator` | validity periods at the validation time |
| `KeyIdentifierValidator` | subject/authority key identifier presence and criticality |

Custom pipelines are created by implementing `ValidatorFactory`; each validator declares the critical extension OIDs it consumes via its return value.

## Critical Extension Handling

Unknown critical extensions reject the path. Validators register which OIDs they consume; any critical extension left unclaimed by the end of the pipeline produces a `CriticalCertificateExtensions` failure, so adding a new extension you do not yet understand fails closed instead of passing silently.
