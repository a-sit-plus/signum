# COSEF explicit header buckets

This rewrite builds on Srdjan Stjepanovic's PRs [#506](https://github.com/a-sit-plus/signum/pull/506) and [#507](https://github.com/a-sit-plus/signum/pull/507). Their 29 source commits remain individually attributed in history. The implementation uses upstream kotlinx.serialization 1.13.0 with Kotlin 2.4.10.

## Application-owned headers

`CoseHeader` is now an interface. Implement separate protected and unprotected models and annotate concrete fields. Interface defaults mean absent parameters; they add no fields to a generated serializer. The old convenience data class is retained in compatibility test fixtures as a migration example. There is no combined header, automatic splitting, or merging.

```kotlin
@Serializable
data class WalletProtectedHeader(
    @CborLabel(1) override val algorithm: CoseAlgorithm,
    @CborLabel(-65537) val walletVersion: Int,
    @SerialName("profile") val profile: String,
    @CborLabel(33)
    @Serializable(with = X5ChainSerializer::class)
    override val certificateChain: List<ByteArray>? = null,
    @CborLabel(2)
    @Serializable(with = CriticalHeadersSerializer::class)
    override val criticalHeaders: List<CoseHeaderLabel>? = null,
) : CoseHeader

@Serializable
data class WalletUnprotectedHeader(
    @CborLabel(4) @ByteString override val kid: ByteArray,
) : CoseHeader
```

Use `CoseContentType` for integer/text content types, `CoseHeaderLabel` for integer/text critical labels, and `CoseCertificateHash` for `x5t`. They carry their reusable serializers. `X5ChainSerializer` encodes a single certificate as a byte string and a chain as an array. Critical lists must be nonempty. Custom nested values and required fields use ordinary generated serializers.

VCK consumers should replace concrete `CoseHeader(...)` calls with their own annotated models, keep PH/UH type arguments separate, and replace `CoseSigned<Payload>` with `CoseSign1<ProtectedHeader, UnprotectedHeader, Payload>`. `CoseHeaderBase`, combined-header wrappers, `CoseTyped`, and the old prepare/sign/create sequence are removed. `CoseSigned`, `CoseMac`, `CoseBytes`, and `CoseInput` exist only as test fixtures; there is no parallel production implementation or JSON wire adapter.

## Signing, decoding, and serialization

```kotlin
val signed = CoseSigner(signer).sign1(protectedHeader, unprotectedHeader, payload)
val encoded = coseCompliantSerializer.encodeToByteArray(signed)
val raw = CoseSign1.Raw<WalletUnprotectedHeader>(encoded)
val typed = raw.typed<WalletProtectedHeader, MyPayload>()
signer.makeVerifier().verify(typed.signatureInput(), typed.signature)
```

Explicit serializers are accepted by `sign1`, `.Raw(bytes, unprotectedHeaderSerializer)`, and `.typed(protectedHeaderSerializer, payloadSerializer)`. Fully protected signing uses `sign1(protectedHeader, payload)` and `EmptyCoseHeader` for the unprotected model. Typed serializers are generated for embedding, or can be built with `CoseSign1Serializer`, `CoseMac0Serializer`, and `CoseSignSerializer`.

`CoseMacCreator(CoseAlgorithm.MAC.HS256, key).mac0(protectedHeader, unprotectedHeader, payload)` creates a MAC using the existing Signum primitive. Validate the returned/decoded tag against the selected trusted algorithm and key before accepting its contents. A supplied key identifier is compared to the creator's identifier when configured. Signers compare `kid` to `publicKey.coseKid` when available; identifiers remain key-selection hints, not trust anchors.

Signers check the declared algorithm, digest, curve, key identifiers, bucket conflicts, critical placement, and critical references before signing. Multiple candidates require an unambiguous key selection. No signature length or certificate issuer-signature algorithm is used to infer the signing algorithm.

## Detached payloads and byte preservation

Pass `detached = true` when creating a detached message. The created typed view exposes `detachedPayload`, the exact serialized bytes to transport externally, without serializing the payload again. Decoding keeps `raw.plainPayload == null`, `isDetached == true`, a null typed payload, and no cached detached bytes. Authentication requires `signatureInput(detachedPayload = originalPayloadBytes)` or `macInput(detachedPayload = originalPayloadBytes)`. Attached empty byte strings remain attached; supplying detached bytes to an attached message is rejected. External AAD must match creation exactly and is never carried in the envelope.

Received protected and payload bytes remain authoritative for authentication and typed serialization, even when map order or integer widths differ from local encoding. New empty protected maps encode as `h''`; both received `h''` and `h'a0'` are preserved. Empty unprotected buckets encode as maps. Envelopes are emitted untagged; recognized incoming CBOR tags are accepted by the upstream format.

Payload creation keeps the legacy wire policy: `ByteArray` is opaque content; other types are CBOR-encoded, wrapped in a byte string, then tagged with tag 24. Decoding accepts direct CBOR and this legacy wrapper. Typed reserialization uses the original payload bytes rather than re-encoding decoded values, including fractional NumericDates. Concrete CWT fields should use the public `InstantLongSerializer` for integer/float NumericDate compatibility.

Raw unprotected headers are **model-dependent**. Ignored fields disappear when that bucket is re-encoded. Keep the entire original input separately for unchanged byte forwarding. This provides neither arbitrary-member inspection nor lossless insertion of unknown unprotected parameters into an enclosing upstream serializer. Protected bytes remain opaque until a protected-header serializer is supplied. Treat published message values and their byte arrays as immutable.

## Critical parameters and conformance boundary

`crit` is protected, nonempty, contains unique labels, and refers to parameters actually present in the protected bucket. Signing requires `processCritical = { label -> ... }` to process each listed parameter; returning false rejects signing. After decoding, applications must similarly process every `typed.protectedHeader.criticalHeaders` entry before accepting a verified message. Structural decoding alone does not process application semantics or establish certificate/key trust.

Modeled labels are tracked where serializers emit or consume fields. Duplicate modeled keys and cross-bucket overlaps are rejected; optional properties merely appearing in a descriptor do not count as present. Unknown fields skipped by upstream decoding are not fully checked for duplicate/conflicting labels. Applications needing stricter conformance must use models that cover their accepted parameters or validate at a separate boundary. No general CBOR parser is introduced here.

The integer/text, `x5chain`, and NumericDate union decoders retain the existing try/catch approach. They depend on upstream CBOR rejecting the wrong major type before consuming the item. Regression tests cover following fields, alternative representations, truncation, and malformed input; recheck those tests when changing serialization versions.

## Multiple signatures and CWT claims

```kotlin
val signed = CoseSigner(listOf(ecSigner, rsaSigner)).sign(
    protectedHeader = bodyProtectedHeader,
    unprotectedHeader = EmptyCoseHeader,
    payload = payload,
    signatures = listOf(
        CoseSignatureParameters(ecProtectedHeader, ecUnprotectedHeader),
        CoseSignatureParameters(rsaProtectedHeader, rsaUnprotectedHeader),
    ),
)
```

Use the same application header types for the signature list, with different algorithm values. `CoseSign.Raw<BodyUnprotectedHeader, SignerUnprotectedHeader>` decodes without protected or payload serializers. Its `.typed<BodyProtectedHeader, SignerProtectedHeader, Payload>()` preserves signature order and each protected encoding. Body and signer parameters must have disjoint modeled labels under this API's explicit conflict policy. Every signer is validated before any signer runs, and all signatures share one payload serialization. `raw.signatureInput(index)` uses the five-element `Signature` context, while Sign1 uses the four-element `Signature1` context. Their wire structures remain distinct even for a single signature.

`CwtClaims` provides the common CWT properties, like `JwtPayload`. Implement it in concrete annotated models and narrow a header's `cwtClaims` property to your concrete claims type. `CborWebToken` also implements this interface for migration. Arbitrary COSE payloads do not have to implement `CwtClaims`.
