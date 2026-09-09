<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../docs/docs/assets/josef-light.png">
  <source media="(prefers-color-scheme: light)" srcset="../docs/docs/assets/josef-dark.png">
  <img alt="Indispensable Josef" src="../docs/docs/assets/josef-dark.png">
</picture>

[![A-SIT Plus Official](https://raw.githubusercontent.com/a-sit-plus/a-sit-plus.github.io/709e802b3e00cb57916cbb254ca5e1a5756ad2a8/A-SIT%20Plus_%20official_opt.svg)](https://plus.a-sit.at/open-source.html)
[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-brightgreen.svg?style=flat)](http://www.apache.org/licenses/LICENSE-2.0)
[![Kotlin](https://img.shields.io/badge/kotlin-multiplatform-orange.svg?logo=kotlin)](http://kotlinlang.org)
[![Kotlin](https://img.shields.io/badge/kotlin-2.3.20-blue.svg?logo=kotlin)](http://kotlinlang.org)
[![Java](https://img.shields.io/badge/java-17+-blue.svg?logo=OPENJDK)](https://www.oracle.com/java/technologies/downloads/#java17)
[![iOS](https://img.shields.io/badge/iOS-15-white?logo=apple)](https://support.apple.com/en-gb/108051)

| [![Android](https://img.shields.io/badge/Android_(indispensable)-SDK--26-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#8.0) |  [![Maven Central (indispensable)](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable?label=maven-central%20%28indispensable%29)](https://mvnrepository.com/artifact/at.asitplus.signum/)  |  [![Maven SNAPSHOT (indispensable)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/indispensable?label=SNAPSHOT%20%28indispensable%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/indispensable/)  |
|:----------------------------------------------------------------------------------------------------------------------------------------------------------:|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------:|
|    [![Android](https://img.shields.io/badge/Android_(Supreme)-SDK--30-37AA55?logo=android)](https://developer.android.com/tools/releases/platforms#11)     |       [![Maven Central (Supreme)](https://img.shields.io/maven-central/v/at.asitplus.signum/supreme?label=maven-central%20%28Supreme%29)](https://mvnrepository.com/artifact/at.asitplus.signum/supreme)        |              [![Maven SNAPSHOT (Supreme)](https://img.shields.io/nexus/snapshots/https/s01.oss.sonatype.org/at.asitplus.signum/supreme?label=SNAPSHOT%20%28Supreme%29)](https://s01.oss.sonatype.org/content/repositories/snapshots/at/asitplus/signum/supreme/)              |
</div>

# Kotlin Multiplatform type-safe JOSE data architecture

Indispensable Josef provides Kotlin Multiplatform models and serializers for JOSE data. It uses
[Kotlinx Serialization](https://github.com/Kotlin/kotlinx.serialization) and interoperates with the cryptographic
types from the `indispensable` module.

## Design principles

A JWS signature covers serialized bytes, not an abstract header and payload. For the supported JWS forms, the signing
input is:

```text
ASCII(BASE64URL(protected-header bytes)) || '.' || ASCII(BASE64URL(payload bytes))
```

Semantically equivalent JSON can have different member order, whitespace, or escaping and therefore different signed
bytes. The library must not parse an incoming protected header into `JwsHeader` and later reserialize it to reconstruct
the signing input. Instead, it keeps the wire/data object as the source of truth and adds typed views around it:

| Layer | Purpose | Main types |
|:--|:--|:--|
| Wire/data | Preserve cryptographically relevant bytes and serialization shape | `JWS`, `JwsCompact`, `JwsFlattened`, `JwsGeneral`, `SignatureElement` |
| Typed/domain | Provide a typed payload while retaining the wire object | `JwsTyped<J, P>` and its compact, flattened, and general aliases |
| Effective header | Combine typed header values and retain their protection status | `JwsHeaderWrapped` |

`JwsTyped` contains the retained `jws` object and its decoded `payload`. Send or store `jws`, not a reconstruction from
`payload`. `JwsTypedSerializerTemplate` serializes only `jws` and derives `payload` again when decoding. Direct users of
the public `JwsTyped` constructor are responsible for keeping both values consistent.

## JWS representation model

| Form | Type | Header representation |
|:--|:--|:--|
| Compact | `JwsCompact` | One protected header; no unprotected header |
| Flattened JSON | `JwsFlattened` | One signature with optional protected and unprotected fragments |
| General JSON | `JwsGeneral` | Shared payload and one or more `SignatureElement`s, each with its own header fragments |

The model distinguishes three header views:

- **Protected as transmitted/signed:** the first compact segment or JSON `protected` member. Its decoded JSON bytes
  are retained in `plainProtectedHeader`, not reduced to a parsed `JwsHeader`.
- **Unprotected:** the optional `unprotectedHeader: JsonObject`. It remains separate and is not signed.
- **Combined/effective:** `wrappedHeader: JwsHeaderWrapped` (or `wrappedHeaders` on `JwsGeneral`). Its `header` is the
  typed strict union of both fragments, while `unprotectedMembers` records which names came from the unprotected one.

A bare `JwsHeader` loses protection status and must not be used for decisions about header placement. Use
`JwsHeaderWrapped` or the original fragments. The wrapper is a one-way typed view: unmodeled parameters remain in
`plainProtectedHeader` or `unprotectedHeader` for round trips, and their unprotected names remain in
`unprotectedMembers`, but their values are not available through `JwsHeader`.

## Serialization invariants

- Incoming signing inputs are derived from the retained `plainProtectedHeader` and `plainPayload` bytes, never by
  reserializing a typed header or payload.
- `plainProtectedHeader`, `plainPayload`, and `plainSignature` contain decoded bytes. Pass plain payload bytes to the
  signing factories; the library handles base64url encoding.
- Header parameters are protected by default. For flattened JWS, only wire names explicitly listed in
  `unprotectedMembers` are unprotected. Protected and unprotected fragments may complement each other, but duplicate
  names are rejected.
- Conversions retain protected bytes and header placement. Because compact JWS has no unprotected header, only a
  fully protected flattened JWS can be converted to compact form; general JWS signatures must share one payload.

## Serialization and verification

Use `joseCompliantSerializer` from `io/Encoding.kt` for JOSE JSON. It disables pretty printing and default-value
encoding, uses `type` as the class discriminator, and ignores unknown keys when decoding typed classes.

The sealed `JWS` serializer preserves the concrete form: JSON strings become `JwsCompact`, objects with `signature`
become `JwsFlattened`, and objects with `signatures` become `JwsGeneral`. Ambiguous or incomplete shapes are rejected.
Use `JwsCompact.toString()`/`JwsCompact(...)` for standalone compact data and `JwsCompactStringSerializer` when the
compact string is embedded in JSON.

Signing factories serialize or partition the header once and pass the resulting exact signing input to the signer.
For verification, use the stored, wire-derived pairs:

- `JwsCompact.signatureInput` and `JwsCompact.signature`;
- `JwsFlattened.signatureInput` and `JwsFlattened.signature`; or
- each corresponding pair in `JwsGeneral.signatureInputs` and `JwsGeneral.signatures`.

Never recreate a signing input from `JwsHeader` or a typed payload. Parsing, typed access, and
`JwsHeader.publicKey` do not verify a signature or establish key trust; callers must perform verification, trust
validation, and application-specific checks. Raw signature conversion currently supports EC and RSA signature
algorithms; unsupported algorithms are rejected.

The older `JwsSigned` API is deprecated in favor of `JwsCompactTyped`.

## JWT payloads

Application payloads may implement `JwtPayload` for standard RFC 7519 claims. Its `@SerialName` annotations are not
inherited, so implementations must declare their own serialization names. `joseCompliantSerializer` ignores unknown
keys when decoding typed payloads.

## Contributing

External contributions are greatly appreciated! Be sure to observe the contribution guidelines (see [CONTRIBUTING.md](../CONTRIBUTING.md)).
In particular, external contributions to this project are subject to the A-SIT Plus Contributor License Agreement (see also [CONTRIBUTING.md](../CONTRIBUTING.md)).

---

| ![eu.svg](../docs/docs/assets/eu.svg) <br> Co&#8209;Funded&nbsp;by&nbsp;the<br>European&nbsp;Union |   This project has received funding from the European Union’s <a href="https://digital-strategy.ec.europa.eu/en/activities/digital-programme">Digital Europe Programme (DIGITAL)</a>, Project 101102655 — POTENTIAL.   |
|:-----------------------------------------------------------------------------------------------:|:-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

---

<p align="center">
The Apache License does not apply to the logos, (including the A-SIT logo) and the project/module name(s), as these are the sole property of
A-SIT/A-SIT Plus GmbH and may not be used in derivative works without explicit permission!
</p>
