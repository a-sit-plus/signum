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
| Typed/domain | Provide a typed payload while retaining the wire object | `JwsTyped<J, P>` and its compact, flattened, and general aliases |
| Effective header | Combine typed header values and retain their protection status | `JwsHeaderWrapped` |

`JwsTyped` contains both the retained `jws` object and its decoded `payload`. Use `jws` when sending or storing the
data. `JwsTypedSerializerTemplate` serializes only this object and derives the typed payload again when decoding.
If you use the public `JwsTyped` constructor directly, you are responsible for keeping `jws` and `payload` consistent.

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
* **Combined:** `wrappedHeader: JwsHeaderWrapped` (or `wrappedHeaders` on `JwsGeneral`) provides the effective header.
  Its `header` is the typed union of both fragments, with duplicate names rejected. Its `unprotectedMembers` records
  which names came from the unprotected fragment.

A bare `JwsHeader` does not retain protection status. Use `JwsHeaderWrapped` or the original fragments whenever
you need to determine whether a header parameter was signed.

The wrapper is a one-way typed view: parameters not modeled by `JwsHeader` remain in `plainProtectedHeader` or
`unprotectedHeader` for round trips, but their values are not available through the typed header. Their unprotected
names are still recorded in `unprotectedMembers`.

### Serialization and Conversion Rules

* Incoming signing inputs are derived from the retained `plainProtectedHeader` and `plainPayload` bytes.
  Typed headers and payloads are never reserialized to reconstruct this input.
* `plainProtectedHeader`, `plainPayload`, and `plainSignature` contain decoded bytes.
  Pass plain payload bytes to the signing factories; the library handles base64url encoding.
* Header parameters are protected by default. When creating a flattened JWS, only wire names explicitly listed in
  `unprotectedMembers` are unprotected. Protected and unprotected fragments can complement each other, but duplicate
  names are rejected.
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

* `JwsCompact.signatureInput` and `JwsCompact.signature`
* `JwsFlattened.signatureInput` and `JwsFlattened.signature`
* Each corresponding pair in `JwsGeneral.signatureInputs` and `JwsGeneral.signatures`

!!! warning
    **Always verify the stored signing input.** Recreating it from `JwsHeader` or a typed payload can change the bytes.
    Parsing, typed access, and `JwsHeader.publicKey` do not verify a signature or establish key trust.
    Your application must perform signature verification, trust validation, and any application-specific checks.

Raw signature conversion currently supports EC and RSA signature algorithms. Unsupported algorithms are rejected.

!!! note
    The older `JwsSigned` API is deprecated. Use `JwsCompactTyped` instead.

## JWT Payloads

Application payloads can implement `JwtPayload` for standard RFC 7519 claims. Its `@SerialName` annotations are not
inherited, so implementations must declare their own serialization names. As with other typed classes,
`joseCompliantSerializer` ignores unknown keys when decoding typed payloads.
