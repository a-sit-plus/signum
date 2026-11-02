# Public certificate-path corpora

`PublicCertificatePathCorpusTests` executes the offline snapshot in
`../resources/corpora/public-paths.json` against `ValidatorFactory.RFC5280`.
No production validator behavior is changed by this import. Upstream expected
acceptance/rejection is preserved; there are no Signum-specific expectation overrides.

| Source | Pinned revision | Imported | Expected rejection | Acceptance controls | Excluded |
|---|---|---:|---:|---:|---:|
| [BoringSSL chain verification](https://github.com/google/boringssl/tree/5d165bc0408b977a80247598834cddd2c99b788f/pki/testdata/verify_certificate_chain_unittest) | `5d165bc0408b977a80247598834cddd2c99b788f` | 75 | 19 | 56 | 122 |
| [OpenSSL verification recipe](https://github.com/openssl/openssl/blob/21909a8a544f88d162ce1d2929cdad5ff990fe11/test/recipes/25-test_verify.t) | `21909a8a544f88d162ce1d2929cdad5ff990fe11` | 42 | 15 | 27 | 163 |
| [Go name constraints](https://github.com/golang/go/blob/a0c8470e9dfe38ac3b594f944238a5678fe9a07e/src/crypto/x509/name_constraints_test.go) | `a0c8470e9dfe38ac3b594f944238a5678fe9a07e` | 109 | 47 | 62 | 12 |
| Total | | 226 | 81 | 145 | 297 |

Every imported case records its source URL, original expectation/error description,
validation time, certificate references, supplied paths/anchors, context options,
expected rejecting validators, and permitted decoding-stage rejection. Exclusions
are individually recorded with source URLs and reasons in the same JSON. The
OpenSSL counts cover 205 statically recognized `ok(verify(...))` assertions, not
its entire recipe: runtime CRL creation and CAfile/CAstore command-line tests are
not standalone path vectors and are not imported.

Acceptance controls are retained to expose implementations which reject an entire
name form or algorithm. The negative side covers signatures, CA/path-length/KU
constraints, validity boundaries, unknown critical extensions and policy qualifiers,
policy processing, and DNS, IP, email and URI name constraints. The OpenSSL
CVE-2022-4203 otherName vector is included.

## Meaning of a test result

* The oracle is the **pinned source expectation**, not the currently installed
  OpenSSL/Go version and not a claim that every source policy is mandatory PKIX.
* The Go table includes interoperability conventions for leading-dot DNS bases,
  empty constraints, unknown name types and wildcard overlap. Differences in those
  cases require standards/policy analysis; they must not automatically be reported
  as RFC violations. Relevant base rules are [RFC 5280 4.2.1.6](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.6)
  and [4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10).
* A negative case must reject **every supplied candidate path**. Rejection for an
  unrelated validator does not pass. Input-decoding errors only pass when that
  stage is explicitly allowed for the vector. An unknown public-key OID is allowed
  to reject at decoding only for BoringSSL's deliberately invalid-SPKI vector.
  Assertions and arbitrary runtime/crypto failures are never caught as rejection passes.
* Positive controls involving optional algorithms/extensions also measure support.
  An unsupported algorithm is an acceptance failure, distinct from accepting an
  invalid chain. RFC 5280 does not require every possible algorithm/extension.
* BoringSSL's golden policy-set output and exact diagnostic wording are retained
  in metadata where present but are **not compared**: this suite checks path
  acceptance/rejection and responsible validators, not full API-output equivalence.
* Go's generator supplies levels of alternative issuers sharing a name/key. The
  exporter enumerates those explicit alternatives, then the harness validates each
  candidate against each supplied anchor. This does not test or implement Signum
  path discovery. OpenSSL's ordered intermediate lists are reversed into leaf-first
  paths; BoringSSL already supplies a leaf-first chain with the anchor last.

Excluded source features include auxiliary trust attributes, special anchor
expiry/constraint/distrust flags, direct-leaf trust, strict TLS/MLS/C2PA purposes,
CA-EKU propagation, algorithm-strength/work limits, proxy certificates, unsupported
CLI options and generated/nonliteral Perl setup. OpenSSL's requirement for a
self-signed terminal anchor without `-partial_chain` is source trust policy;
[RFC 5280 6.1.1(d)](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.1)
permits the explicitly trusted key/name form used by Signum. That rollover-vector
rejection is therefore recorded as an exclusion, not an RFC rejection expectation.

## Re-import

From the repository root:

```sh
python3 pkix-supreme/src/jvmTest/corpora/import_corpora.py --cache /tmp/signum-public-corpora
```

The importer uses Python's standard library, curl and Go, with no package downloads.
It verifies archive revision names and copies only certificates, expected results,
source metadata and license notices into resources. Private keys are not imported.

Go's source generates certificates at test time. `export_go.go.txt` is appended to
its pinned types, tables and unmodified certificate generators. The committed
snapshot was generated with **Go 1.21.6**; that toolchain is recorded, not used as an
expectation oracle. The validation time is the upstream `time.Unix(1500, 0)`.
A fresh import re-signs Go fixtures with ephemeral keys, so semantics are repeatable
but certificate bytes differ; a cached export is reused while its generator
fingerprint is unchanged. OpenSSL uses explicit upstream `-attime` where supplied,
otherwise the snapshot time 2026-11-02. BoringSSL's `DEFAULT` is the upstream helper's
2021-10-05T12:00:00Z. Normal JVM runs need none of these generation tools.

Source copyright/license notices accompany the JSON:

* BoringSSL pki tests: Copyright 2015-2016 The Chromium Authors; Apache-2.0,
  `LICENSE-BoringSSL`.
* OpenSSL tests/certificates: Copyright 2015-2026 The OpenSSL Project Authors;
  Apache-2.0, `LICENSE-OpenSSL`.
* Go name-constraints tests/generators: Copyright 2017 The Go Authors; BSD-style,
  `LICENSE-Go`.

The adapter and normalized JSON are modifications for Signum; they are not
unmodified upstream test runners. The source revision and per-case URL identify
which original table/recipe defines each expectation.

## Optional native reference check

```sh
python3 pkix-supreme/src/jvmTest/corpora/import_corpora.py --check-openssl
```

This compares the 42 imported OpenSSL cases with the installed executable and
writes `../resources/corpora/reference-openssl.json` without changing expectations.
OpenSSL 4.0.3 differs from the pinned newer recipe on five acceptance controls:
two DSA/SHA-384/512 algorithm cases and three CN-fallback name-constraint cases.
These differences are recorded rather than used to rewrite the source oracle.

## Recorded Signum results (2026-11-02)

No production fixes accompany this import. The 226 cases currently produce:

| Source | Passed | Failed | Expected-rejection cases incorrectly accepted |
|---|---:|---:|---:|
| BoringSSL | 72 | 3 | 1 |
| OpenSSL | 29 | 13 | 4 |
| Go | 81 | 28 | 6 |
| Total | 182 | 44 | 11 |

The 44 failures comprise **11 unexpected acceptances**, **24 unexpected
rejections**, and **9 algorithm/decoder support differences**. They are not 44
independent vulnerabilities. The full PKIX Supreme JVM suite has 551 tests,
504 passing and 47 failing, including the three previously recorded local gaps.

The 11 unexpected acceptances are:

* BoringSSL `unknown-critical-policy-qualifier/main.test`.
* Go table entries 036/037 (IPv4/IPv6 permitted-constraint mismatch),
  054 (case-sensitive mailbox local-part), and 109/119/120 (wildcard/exclusion
  overlap and case handling).
* OpenSSL recipe lines 424 (explicit EC parameters), 534/537 (email name
  constraints), and 686 (explicit policy rejection).

The source links in the JSON point to each exact pinned test. Relevant standards
for triage include [RFC 5280 4.2.1.10](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.10)
for name constraints, [7.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-7.5)
for exact mailbox local-part matching, [4.2.1.4](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.2.1.4)
for critical policy qualifiers, [6.1.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.5)
for final policy processing, and [RFC 5480 2.1.1](https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1)
for EC parameters. Wildcard-overlap expectations remain Go interoperability
expectations pending a separate policy review.

`../resources/corpora/public-path-results.json` records every failed case, its
source URL, expectation, category and diagnostic, tied to the corpus SHA-256.
The automatic categories describe observed outcomes and are not a root-cause
analysis. Diagnostics longer than 4096 characters are explicitly marked truncated;
the complete JUnit report remains under `pkix-supreme/build/test-results/jvmTest`.
Update the record after a run with:

```sh
python3 pkix-supreme/src/jvmTest/corpora/import_corpora.py --record-junit \
  pkix-supreme/build/test-results/jvmTest/TEST-suite_at.asitplus.signum.supreme.validate.PublicCertificatePathCorpusTests.xml
```
