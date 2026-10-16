![indispensable-josef](assets/josef-dark-large.png#only-light) ![indispensable-josef](assets/josef-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable-josef?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum.indispensable-josef/)

# Indispensable JOSE Data Structures

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent JOSE data
types, predefined algorithm identifiers, and serializers based on kotlinx.serialization.
_Indispensable Josef_ interoperates with [Indispensable](indispensable.md) data classes such as `SignatureAlgorithm`,
`CryptoSignature`, and `CryptoPublicKey`. Its JWS models preserve the bytes used for signing while providing typed
access to headers and payloads.

!!! tip
    **Check out the [full API docs](dokka/indispensable-josef/index.html)** for an overview of all JOSE-specific data types!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it supports all KMP targets except `watchosDeviceArm64`.

Simply declare the desired dependency to get going:

```kotlin
implementation("at.asitplus.signum:indispensable-josef:$version")
```

## Key Design Principles

A JWS signature covers serialized bytes. Even if two JSON documents contain the same header values or payload,
differences in member order, whitespace, or escaping can change those bytes. For the supported JWS forms, the signing
input is:

```text
ASCII(BASE64URL(protected-header bytes)) || '.' || ASCII(BASE64URL(payload bytes))
```

To preserve this input, _Indispensable Josef_ retains the received data and provides typed views around it.
Parsing a protected header into `JwsHeader` and serializing it again could produce different bytes, so the typed
view is never used to reconstruct an incoming signing input.

| Layer | Purpose | Main Types |
|:--|:--|:--|
| Wire/data | Preserve cryptographically relevant bytes and serialization shape | `JWS`, `JwsCompact`, `JwsFlattened`, `JwsGeneral`, `SignatureElement` |
| Typed/domain | Decode payloads, custom headers, and signatures while retaining the wire object | `JwsTyped<J, P, H>` and its compact, flattened, and general views |
| Effective header | Combine modeled header values and retain their protection status | `JwsHeaderWrapped<H>` with `H : JwsHeaderBase` |

`JwsTyped` is a sealed base for concrete compact, flattened, and general views. Each retains its original `jws`
and decoded `payload`. Compact and flattened views expose `header`, `unprotectedHeaderMembers`, and `signature`;
general views expose ordered `headers`, `unprotectedHeaderMembers`, and `signatures`. Wire objects retain bytes
and fragments without eagerly decoding headers or signatures. Use `jws` when sending or storing data.
`JwsTypedSerializerTemplate` serializes only that object and derives the decoded values again when decoding.
Direct users of concrete typed constructors must keep the decoded values consistent with the retained wire object.

## JWS Representations

The library supports three JWS forms:

| Form | Type | Header Representation |
|:--|:--|:--|
| Compact | `JwsCompact` | One protected header; no unprotected header |
| Flattened JSON | `JwsFlattened` | One signature with optional protected and unprotected fragments |
| General JSON | `JwsGeneral` | Shared payload and one or more `SignatureElement`s, each with its own header fragments |

### Protected and Unprotected Headers

Each signature exposes three views of its header:

* **Protected:** The first compact segment or the JSON `protected` member contains the signed header.
  Its decoded JSON bytes are retained in `plainProtectedHeader`.
* **Unprotected:** The optional `unprotectedHeader: JsonObject` remains separate and is not signed.
* **Combined:** `header: H` on compact/flattened typed views, or ordered `headers: List<H>` on general views,
  combines each signature's fragments, rejecting duplicate names. `unprotectedHeaderMembers` contains the unprotected
  wire names emitted by the header serializer, with one set per signature on general views.

A typed header alone does not retain protection status. Use the typed view's placement metadata or original fragments
to check placement. Unmodeled parameters remain in the original fragments for round trips; forward the retained `jws`.

### Serialization and Conversion Rules

* Incoming signing inputs are derived from the retained `plainProtectedHeader` and `plainPayload` bytes.
  Typed headers and payloads are never reserialized to reconstruct this input.
* `plainProtectedHeader`, `plainPayload`, and `plainSignature` contain decoded bytes.
  Pass plain payload bytes to the signing factories; the library handles base64url encoding.
* Header parameters are protected by default. When constructing `JwsHeaderWrapped`, wire names listed in its
  `unprotectedMembers` argument are unprotected; `unprotectedHeaderMembers` exposes the represented names. Protected
  and unprotected fragments can complement each other, but duplicate names are rejected during typed decoding.
* Conversions retain protected bytes and header placement. Compact JWS has no unprotected header, so only a fully
  protected flattened JWS can be converted to compact form. General JWS signatures must share one payload.

## Serialization and Verification

### Encoding and Decoding

Use `joseCompliantSerializer` for JOSE JSON. This preconfigured serializer disables pretty printing and default-value
encoding, uses `type` as the class discriminator, and ignores unknown keys when decoding typed classes.

The sealed `JWS` serializer preserves the concrete form:

* JSON strings become `JwsCompact`.
* Objects with `signature` become `JwsFlattened`.
* Objects with `signatures` become `JwsGeneral`.

Ambiguous or incomplete shapes are rejected. Use `JwsCompact.toString()` and `JwsCompact(...)` for standalone compact
data, and `JwsCompactStringSerializer` when embedding a compact string in JSON.

### Signing and Verification

Signing factories serialize or partition the header once and pass the resulting exact signing input to the signer.
To verify a signature, use the stored input and signature pairs:

* `typedCompact.jws.signatureInput` and `typedCompact.signature`
* `typedFlattened.jws.signatureInput` and `typedFlattened.signature`
* Each `view.jws.signatureInput` and `view.signature` from `typedGeneral.toJwsFlattenedTyped()`

!!! warning
    **Always verify the stored signing input.** Recreating it from `JwsHeader` or a typed payload can change the bytes.
    Parsing, typed access, and `JwsHeader.publicKey` do not verify a signature or establish key trust.
    Your application must perform signature verification, trust validation, and any application-specific checks.

Wire objects can retain opaque headers and unsupported signature algorithms. Creating a typed view decodes headers
and converts raw signatures; conversion currently supports EC and RSA signature algorithms and rejects unsupported
algorithms. Typed decoding does not handle critical extensions on behalf of the application.

!!! note
    The older `JwsSigned` API is deprecated. Use `JwsCompactTyped` instead.

## Custom Headers and Typed Access

Define a serializable model implementing `JwsHeaderBase`. Interface serialization annotations are not inherited:
implementations must declare wire names and serializers, or mark unmodeled properties as `@Transient`.

```kotlin
val typed = JwsCompact(receivedCompactString).typed<JsonObject, AppHeader>()
val header: AppHeader = typed.header
val signingInput = typed.jws.signatureInput
val wrapped = JwsHeaderWrapped(header, setOf("app_claim"))
val explicit = JwsHeaderWrapped(header, AppHeader.serializer(), setOf("app_claim"))
```

Reified `.typed<P, H>(serialFormat)` uses the supplied JSON configuration. Explicit serializers are supported through
`.typed(payloadSerializer, headerSerializer, serialFormat)`. `JwsTypedSerializerTemplate` takes the wire, payload,
and header serializers and uses `joseCompliantSerializer` for decoded views. Contextual serialization is out of scope.
The callback signing helpers are deprecated pending a signing service.

### Migration

| Previous API | Replacement |
|:--|:--|
| Typed aliases such as `JwsCompactTyped<P>` | Concrete views such as `JwsCompactTyped<P, H>` |
| Header/signature properties on wire objects | Header/signature properties on typed views |
| `jws.typed<J, P>()` | `jws.typed<P, H>()` on the concrete wire form |
| `JwsCompact.parse<P>()` returning a pair | `JwsCompact.parse<P, H>()` returning wire object, payload, and wrapped header as a triple |
| Two-argument `JwsTypedSerializerTemplate` | Add the header serializer as the third argument |
| Payload-signing `JwsTyped` factories | Construct the wire form from payload bytes, then call `.typed<P, H>()` |
| `JwsFlattened(header, payload, unprotectedMembers, signer)` | `JwsFlattened(JwsHeaderWrapped(header, unprotectedMembers), payload, signer)` |
| Named `getPayload(serialFormat = ...)` argument | `getPayload(payloadFormat = ...)` |

`JwsHeader` remains available but is deprecated in favor of application-defined models implementing `JwsHeaderBase`.

## JWT Payloads

Application payloads can implement `JwtPayload` for standard RFC 7519 claims. Its `@SerialName` annotations are not
inherited, so implementations must declare their own serialization names. As with other typed classes,
`joseCompliantSerializer` ignores unknown keys when decoding typed payloads.
