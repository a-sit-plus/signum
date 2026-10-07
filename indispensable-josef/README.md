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
| Typed/domain | Decode payloads, custom headers, and signatures while retaining the wire object | `JwsTyped<J, P, H>`, `JwsCompactTyped<P, H>`, `JwsFlattenedTyped<P, H>`, `JwsGeneralTyped<P, H>` |
| Effective header | Combine modeled header values and retain their protection status | `JwsHeaderWrapped<H>` with `H : JwsHeaderBase` |

`JwsTyped` is a sealed base for three concrete typed views. Each retains its original `jws` and decoded `payload`.
Compact and flattened views also expose `wrappedHeader` and `signature`; general views expose ordered
`wrappedHeaders` and `signatures`. Wire objects retain bytes and fragments without eagerly decoding a header model
or signature. Send or store `jws`. `JwsTypedSerializerTemplate` serializes only that wire object and derives all typed
values when decoding. Direct users of the concrete typed constructors must keep those values consistent.

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
- **Combined/effective:** `wrappedHeader: JwsHeaderWrapped<H>` on compact/flattened typed views, or
  `wrappedHeaders` on a general typed view. Its `header` is the typed strict union of both fragments, while
  `unprotectedMembers` records which wire names came from the unprotected one.

A bare header model loses protection status. Use `JwsHeaderWrapped<H>` or the original fragments when checking
placement. `effectiveUnprotectedMembers` contains only names represented by the serialized model. Wrapper equality
uses the modeled header and this effective placement; absent or unmodeled names do not affect equality.

The wrapper retains its header serializer and can produce protected bytes with `toProtectedHeader()` and unprotected
JSON with `toUnprotectedHeader()` when constructing a new JWS. These methods serialize only modeled parameters.
Unmodeled values remain in the original wire fragments for round trips; use the retained `jws` for forwarding and
verification, rather than reconstructing it from the wrapper.

## Serialization invariants

- Incoming signing inputs are derived from the retained `plainProtectedHeader` and `plainPayload` bytes, never by
  reserializing a typed header or payload.
- `plainProtectedHeader`, `plainPayload`, and `plainSignature` contain decoded bytes. Pass plain payload bytes to the
  signing factories; the library handles base64url encoding.
- Header parameters are protected by default. For flattened JWS, only wire names explicitly listed in
  `unprotectedMembers` are unprotected. Protected and unprotected fragments may complement each other, but duplicate
  names are rejected when decoding a typed header.
- Conversions retain protected bytes and header placement. Because compact JWS has no unprotected header, only a
  fully protected flattened JWS can be converted to compact form; general JWS signatures must share one payload.

## Serialization and verification

Use `joseCompliantSerializer` from `io/Encoding.kt` for JOSE JSON. It disables pretty printing and default-value
encoding, uses `type` as the class discriminator, and ignores unknown keys when decoding typed classes.

Contextual serialization is generally considered out of scope unless a concrete use case arises.

The sealed `JWS` serializer preserves the concrete form: JSON strings become `JwsCompact`, objects with `signature`
become `JwsFlattened`, and objects with `signatures` become `JwsGeneral`. Ambiguous or incomplete shapes are rejected.
Use `JwsCompact.toString()`/`JwsCompact(...)` for standalone compact data and `JwsCompactStringSerializer` when the
compact string is embedded in JSON.

Signing factories serialize or partition the header once and pass the resulting exact signing input to the signer.
For verification, use the stored, wire-derived pairs:

- `typedCompact.jws.signatureInput` and `typedCompact.signature`;
- `typedFlattened.jws.signatureInput` and `typedFlattened.signature`; or
- each corresponding pair in `typedGeneral.jws.signatureInputs` and `typedGeneral.signatures`.

Never recreate a signing input from a modeled header or typed payload. Parsing, typed access, and
`JwsHeader.publicKey` do not verify a signature or establish key trust; callers must perform verification, trust
validation, and application-specific checks. Raw signature conversion currently supports EC and RSA signature
algorithms; unsupported algorithms are rejected.

The older `JwsSigned` API is deprecated in favor of `JwsCompactTyped`.

## Custom JWS headers

Define a serializable model implementing `JwsHeaderBase`. Serialization annotations on the interface are not
inherited: declare wire names and any custom serializers on the implementation. Properties the application does
not model can return `null` and be marked `@Transient`.

```kotlin
@Serializable
data class AppHeader(
    @SerialName("alg") override val algorithm: JwsAlgorithm,
    @SerialName("kid") override val keyId: String? = null,
    @SerialName("app_claim") val applicationClaim: String? = null,
    override val crit: List<String>? = null,
) : JwsHeaderBase {
    @Transient override val type: String? = null
    @Transient override val contentType: String? = null
    @Transient override val certificateChain: CertificateChain? = null
    @Transient override val jsonWebKey: JsonWebKey? = null
    @Transient override val jsonWebKeySetUrl: String? = null
    @Transient override val certificateUrl: String? = null
    @Transient override val certificateSha1Thumbprint: ByteArray? = null
    @Transient override val certificateSha256Thumbprint: ByteArray? = null
}

val typed = JwsCompact(receivedCompactString).typed<JsonObject, AppHeader>()
val claim = typed.wrappedHeader.header.applicationClaim
val signingInput = typed.jws.signatureInput

val header = AppHeader(JwsAlgorithm.Signature.RS256, applicationClaim = "example")
val wrapped = JwsHeaderWrapped(header, setOf("app_claim"))
// Use an explicit serializer when the header type is not reified at the call site.
val explicit = JwsHeaderWrapped(header, AppHeader.serializer(), setOf("app_claim"))
```

Compact JWS cannot carry represented unprotected members. Flattened JWS can partition a wrapped header using its
wire member names. The callback-based `JwsCompact` and `JwsFlattened` signing helpers are deprecated pending a
signing service; pass plain payload bytes and use the exact input supplied to the callback.

To serialize a typed view through its retained wire object:

```kotlin
val serializer = JwsTypedSerializerTemplate(
    JwsCompactStringSerializer,
    JsonObject.serializer(),
    AppHeader.serializer(),
)
val encoded = joseCompliantSerializer.encodeToString(serializer, typed)
val decoded = joseCompliantSerializer.decodeFromString(serializer, encoded)
```

Use `JwsFlattened.serializer()`, `JwsGeneral.serializer()`, or `JWS.serializer()` as the first argument for those
wire forms. Reified `.typed<P, H>(serialFormat)` uses the supplied JSON format for payload and header decoding.
The serializer template uses `joseCompliantSerializer` for those decoded views.

## Migrating header and typed access

| Previous API | Replacement |
|:--|:--|
| `JwsHeader` as the only modeled header | A serializable implementation of `JwsHeaderBase`; `JwsHeader` remains available but deprecated |
| `JwsCompactTyped<P>` and the other typed aliases | Concrete `JwsCompactTyped<P, H>`, `JwsFlattenedTyped<P, H>`, and `JwsGeneralTyped<P, H>` |
| `jws.typed<J, P>()` | `jws.typed<P, H>()` on the concrete wire form |
| Header/signature properties on wire objects | Header/signature properties on their typed views |
| `JwsCompact.parse<P>()` returning a pair | `JwsCompact.parse<P, H>()` returning wire object, payload, and wrapped header as a triple |
| Two-argument `JwsTypedSerializerTemplate` | Add the header serializer as the third argument |
| Payload-signing `JwsTyped` factories | Construct the wire form from payload bytes, then call `.typed<P, H>()` |
| `JwsFlattened(header, payload, unprotectedMembers, signer)` | `JwsFlattened(JwsHeaderWrapped(header, unprotectedMembers), payload, signer)` |
| Named `getPayload(serialFormat = ...)` argument | `getPayload(payloadFormat = ...)` |

`JwsHeader.Part` remains removed. A wire object can retain opaque headers and unsupported signature algorithms;
creating a typed view performs header decoding and supported-signature conversion. Neither operation verifies the
signature or handles critical extensions on behalf of the application.

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
