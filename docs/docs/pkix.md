# **PKIX** X.509 Parsing &amp; Path Validation

The PKIX modules provide typed X.509 data structures and an experimental, configurable certificate path validator for Kotlin Multiplatform.

* **Indispensable PKIX** (indispensable-pkix) parses certificates, CRLs, and CSR data into typed, immutable Kotlin models &rarr; no reflection, no stringly-typed extension handling
* **Signum Supreme PKIX** (pkix-supreme) attaches trust anchors to a supplied path and provides the `ValidatorFactory.RFC5280` preset targeting [RFC 5280 section 6.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1). Its scope and remaining limitations are described below; the preset name does not guarantee complete conformance.

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

The simplest way to validate a certificate chain is to build the path against a set of trust anchors and run the basic path-validation preset:

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
* `BuildPathFailure` &mdash; no candidate path validated; the map contains failures from attempted paths and can be empty if no anchor matched

If you already have an anchored chain, call `AnchoredCertificateChain.validate` directly. Both entry points accept a custom `ValidatorFactory` to add application policy or optional issuance checks.

### Configuration Knobs

`CertificateValidationContext` controls validation behaviour:

* `date` &mdash; the validation time (defaults to the system clock)
* `initialPolicies` / `explicitPolicyRequired` &mdash; certificate policy processing
* `policyMappingInhibited`, `anyPolicyInhibited`, `policyQualifiersRejected` &mdash; policy flags from the PKIX profile
* `expectedEku` &mdash; requested leaf purposes checked **if EKU is present**; absent EKU remains unrestricted. Requiring EKU presence is separate application policy allowed by [4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12). This does not propagate CA EKUs through a TLS path.
* `leafKeyUsageCheck` &mdash; additional application-specific leaf key-usage checks; the default does nothing
* `supportRevocationChecking` &mdash; legacy name for an additional cRLSign check on path CAs whose KU is present. **It does not check revocation status.** Actual CRL signer validation is specified in [6.3.3(f)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.3.3).
* `allowIncludedTrustAnchor` &mdash; whether a trust anchor certificate may already be part of the submitted chain
* `trustAnchors` &mdash; the anchor set (defaults to the system trust store, falling back to the bundled one)

## Basic Path Validation, Issuance Conformance, and TLS Policy

[RFC 5280 section 6.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1) deliberately separates certification-path validity from conformance to the certificate issuance profile in section 4. Its algorithm recommends against adding full profile-conformance checks. The default `RFC5280` preset targets that basic algorithm; stricter issuance or application rules must be requested explicitly.

This distinction changes observable behavior:

| Input | Basic path preset | Additional rule and source |
|---|---|---|
| CA in the path has no KU | Does not reject solely for absent KU | If KU exists, keyCertSign is required by [6.1.4(n)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4). Issuers must include KU under [4.2.1.3](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.3). |
| CA has noncritical basicConstraints | Processes CA flag and path length | Criticality is an issuance requirement in [4.2.1.9](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.9). |
| Noncritical name/policy constraints | Processes recognized constraints | Issuance criticality requirements are in [4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10) and [4.2.1.11](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.11). |
| Missing SKI/AKI or unusual serial | No mandatory issuance linting | These issuer obligations appear in [4.2.1.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.1), [4.2.1.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.2), and [4.1.2.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.2). |
| `CN=Alice`, no DNS SAN | Does not invent a DNS identity from CN | [6.1.3(b)-(c)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3) constrains the subject DN as directoryName and SANs by their actual types. |
| Certificate validity extends outside its issuer's interval | Checks each path certificate at the evaluation time | Interval nesting is not required by [6.1.3(a)(2)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3). |
| Leaf has no EKU | Does not reject solely for absent EKU | Applications may require it under [4.2.1.12](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.12); TLS issuance profiles have additional requirements. |

`CertValidityValidator` and `KeyIdentifierValidator` remain available for **partial, optional issuance linting**. They are no longer included in `RFC5280`. For example:

```kotlin
val withIssuanceChecks = ValidatorFactory { context ->
    with(ValidatorFactory.RFC5280) { generate(context) } +
        listOf(CertValidityValidator(), KeyIdentifierValidator())
}
val result = chain.buildPathAndValidate(withIssuanceChecks, context)
```

Those two checkers do not implement the whole section 4 profile. For example, `KeyIdentifierValidator` checks AKI on the anchor and its immediate child, not every path certificate. `checkCaBasicConstraints` is a separate optional CA-profile helper.

## Trust Anchors

Both certificate-form and public-key anchors supply trusted names and keys. The anchor certificate is not a member of the path and is not subjected to its own validity, basicConstraints, KU, SKI/AKI, or unknown-critical-extension checks by the basic preset. See [6.1.1(d)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1).

The implementation uses an anchor's name constraints as initial input. This is an explicit local policy: [RFC 6818 section 4](https://www.rfc-editor.org/rfc/rfc6818.html#section-4) permits using additional anchor information. Anchor pathLenConstraint is not automatically applied. `allowIncludedTrustAnchor` controls removal of an explicitly supplied anchor certificate from the submitted path.

## Preset Validators

| Validator | Basic-path responsibility |
|---|---|
| `PolicyValidator` | Policy tree and policy constraints: [6.1.3(d)-(f)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3), [6.1.4(a)-(j)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4), [6.1.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.5) |
| `NameConstraintsValidator` | Name constraints and SAN handling: [6.1.3(b)-(c)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3), [6.1.4(g)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4) |
| `KeyUsageValidator` | Conditional CA KU check: [6.1.4(n)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4); optional context-specified leaf purpose checks |
| `BasicConstraintsValidator` | CA flag and path length: [6.1.4(k)-(m)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4) |
| `ChainValidator` | Signature and issuer-name integrity: [6.1.3(a)(1),(4)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3) |
| `TimeValidityValidator` | Evaluation time inside each path certificate's validity: [6.1.3(a)(2)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3) |

Custom validators return the critical extension OIDs they process for each certificate. Unclaimed critical path extensions reject validation; recognized relevant noncritical extensions are still processed. See [6.1.4(o)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.4) and [6.1.5(f)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.5). Decoder rejection (for example, duplicate extensions or mismatched signature algorithms) is tested separately from returned path-validation failures.

## Implementation and Test Coverage Limits

* **Revocation remains a prerequisite for the caller.** [6.1.3(a)(3)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3) requires a non-revoked certificate. This preset does not fetch or validate CRLs or OCSP responses. A `Success` result alone does not establish every condition in section 6.1.
* **Path discovery is limited.** The constructor attaches applicable anchors to a fixed, ordered input path. It does not search unordered issuer pools, discover alternate intermediate paths, or implement direct trust of the target as a zero-length path. Path discovery is outside the section 6.1 algorithm, but these are practical API limitations.
* **This is not a TLS/WebPKI verifier.** There is no peer-name verification, CA EKU propagation, or complete CABF certificate-profile enforcement. A WebPKI preset is deferred. Service identity is specified separately by [RFC 9525 section 6](https://www.rfc-editor.org/rfc/rfc9525.html#section-6); public TLS issuance rules are in the [CABF Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/requirements/).
* **Time precision is a documented interoperability choice.** The implementation floors the validation time to seconds. Limbo calls its fractional-notAfter case ambiguous; its success expectation is not treated as an unambiguous RFC requirement. See the [Limbo validity vectors](https://x509-limbo.com/testcases/rfc5280/) and [4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5).
* **Name matching and extensions need further conformance work.** Issuer DN comparison currently uses a textual normalization rather than implementing every rule in [7.1](https://www.rfc-editor.org/rfc/rfc5280.html#section-7.1). The chain checker also retains a legacy unique-ID equality restriction, additional to basic validation; [4.1.2.8](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.8) specifies no UID processing requirements. GeneralSubtree minimum/maximum are decoded but are not enforced by constraint matching; [4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10) requires processing them or rejecting certificates using unsupported values when the constrained name form appears. Malformed critical NameConstraints can also decode to empty constraints rather than rejecting the certificate, contrary to [4.2](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2). A passing imported subset is not an exhaustive conformance claim.

The test suites distinguish the following contracts:

| Suite | What it establishes and what it excludes |
|---|---|
| `NistPkitsPathTests` | 151 imported [NIST PKITS](https://csrc.nist.gov/projects/pki-testing) cases targeting X.509/RFC 3280, evaluated at a fixed date. Assertions are never caught as expected rejections. Two locally inverted valid-notBefore expectations were restored from PKITS 4.2.3/4.2.4. CRL-signing KU cases test only the KU prerequisite; no CRL tests are imported. Failures identify the responsible validator without matching implementation-specific error prose. |
| `LimboRfc5280PathTests` | Selected RFC-labelled, path-length, and saved online vectors from [x509-limbo](https://github.com/C2SP/x509-limbo). Upstream JSON expectations are preserved. Each different basic-path expectation has a reason in the adapter. Optional issuance linting has its own context. All seven validity-time cases run; saved online vectors use their recorded times and make no network requests. |
| Local DER regressions | State exactly whether they test basic paths, optional issuance linting, or application policy. The previous leading-dot fixture is a negative subtree test: `.allowed.example` cannot permit `nc2.good.example`. The single-CA permitted-subtree fixture tests alternatives, not intersection across CAs. |

The Limbo adapter explicitly excludes alternate-path/reordering cases, caller-specified `max_chain_depth`, two vectors missing their described intermediate (`intermediate-ca-missing-basic-constraints`, `ica-ku-keycertsign`), and the directly trusted peer in `serial::negative`. The latter's serial is still tested by optional issuance linting. It does not consume expected peer names, validation kind, signature-algorithm policy, requested leaf KU, or CRLs. These exclusions must not be counted as tested capabilities.

### Recorded JVM Status

The 2026-11-02 run of `./gradlew :indispensable-pkix:jvmTest :pkix-supreme:jvmTest --console=plain` produced:

| Scope | Passed | Failed |
|---|---:|---:|
| `indispensable-pkix` | 125 | 0 |
| `pkix-supreme` | 322 | 3 |
| NIST imported path cases (included above) | 151 | 0 |
| Limbo basic-path/decoder cases (included above) | 105 | 0 |
| Limbo optional issuance checks (included above) | 12 | 0 |

The three active `KNOWN RFC 5280 GAP` regressions in `PkixDerRegressionTest` require rejection or proper handling of critical DNS subtree `minimum=2`, `maximum=0`, and malformed critical NameConstraints. They isolate the extension validator so an unrelated signature failure cannot make them pass. They are neither skipped nor inverted to bless current behavior; the JVM build remains red until those implementation gaps are addressed. Android and native tests were not run in this pass.
