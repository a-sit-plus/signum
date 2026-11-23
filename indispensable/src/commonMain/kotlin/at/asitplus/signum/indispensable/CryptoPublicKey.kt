package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.io.MultiBase
import at.asitplus.io.UVarInt
import at.asitplus.io.multibaseDecode
import at.asitplus.io.multibaseEncode
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/**
 * Representation of a public key structure
 */
interface CryptoPublicKey : WithSourceRepresentation {

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or Cose Keys may define an arbitrary key IDs.
     * This is not meant for Algorithm parameters! If an algorithm needs parameters, the implementing classes should be extended
     */
    //must be serializable, therefore <String,String>
    val additionalProperties: MutableMap<String, String>

    /** Representation of the key in DID format, using the `did:key` method */
    val didEncoded: String get() =
        PREFIX_DID_KEY +
                (didCodec.encodeToByteArray() + didKeyBytes).multibaseEncode(MultiBase.Base.BASE58_BTC)

    /**
     * Representation of the key in DID format, using the [`did:jwk`](https://github.com/quartzjer/did-jwk/blob/main/spec.md) method,
     * i.e. `did:jwk:` followed by the base64url-encoded (unpadded) JSON serialization of the public JWK.
     * The JWK contains only the members required by [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html#section-3.2),
     * ordered lexicographically, so the result is deterministic.
     */
    val didJwkEncoded: String get() {
        val jwk = ServiceLoader.load<Asn1PublicKeyFormatProvider>().get(this) { encodeToDidJwk(it) }
        val sorted = JsonObject(jwk.entries.sortedBy { it.key }.associate { it.toPair() })
        return PREFIX_DID_JWK + Json.encodeToString(JsonObject.serializer(), sorted)
            .encodeToByteArray().encodeToString(Base64UrlStrict)
    }
    val didCodec: UVarInt
    val didKeyBytes: ByteArray

    @SignumInternals
    class Unknown(lookupResult: UnsupportedCryptoException)
        : CryptoPublicKey, ServiceLoader.UnknownShim(lookupResult) {
        override val didKeyBytes get() = fails
        override val didCodec get() = fails
        override val additionalProperties: MutableMap<String, String> get() = fails
    }

    companion object {
        init { Signum.installIndispensable() }

        /**
         * Parses a DID representation of a public key (either `did:key` or `did:jwk`) and
         * reconstructs the corresponding [CryptoPublicKey] from it.
         * A DID URL fragment (e.g. `#0`) is ignored.
         * @throws Throwable all sorts of exception on invalid input
         */
        @Throws(Throwable::class)
        fun fromDid(input: String): CryptoPublicKey = when {
            input.startsWith(PREFIX_DID_KEY) -> fromDidKey(input.removePrefix(PREFIX_DID_KEY).substringBefore("#"))
            input.startsWith(PREFIX_DID_JWK) -> fromDidJwk(input.removePrefix(PREFIX_DID_JWK).substringBefore("#"))
            else -> throw IllegalArgumentException("Input does not specify public key")
        }

        private fun fromDidKey(bytes: String): CryptoPublicKey {
            val decoded = catching { bytes.multibaseDecode() }.getOrThrow()
                ?: throw IndexOutOfBoundsException("Unsupported multibase encoding")
            val (codec, codecLength) = UVarInt.fromByteArrayPermissive(decoded)
            val keyBytes = decoded.copyOfRange(codecLength, decoded.size)

            return ServiceLoader.load<Asn1PublicKeyFormatProvider>().get(codec) {
                decodeFromDidKey(it, keyBytes)
            }
        }

        private fun fromDidJwk(encoded: String): CryptoPublicKey {
            val jwk = Json.parseToJsonElement(encoded.decodeToByteArray(Base64UrlStrict).decodeToString()).jsonObject
            DID_JWK_PRIVATE_MEMBERS.firstOrNull { it in jwk }?.let {
                throw IllegalArgumentException("did:jwk must not contain private key material (found \"$it\")")
            }
            return ServiceLoader.load<Asn1PublicKeyFormatProvider>().get(jwk) { decodeFromDidJwk(it) }
        }

    }

    @Deprecated(message = "Public key types migrated out of CryptoPublicKey as part of providerization",
        replaceWith = ReplaceWith("EcdsaPublicKey"))
    typealias EC = EcdsaPublicKey
    @Deprecated(message = "Public key types migrated out of CryptoPublicKey as part of providerization",
        replaceWith = ReplaceWith("RsaPublicKey"))
    typealias RSA = RsaPublicKey
}

interface SpecializedCryptoPublicKey {
    fun toCryptoPublicKey(): KmmResult<CryptoPublicKey>
}

/** Alias of [equals] provided for convenience (and alignment with [SpecializedCryptoPublicKey]) */
fun CryptoPublicKey.equalsCryptographically(other: CryptoPublicKey) =
    equals(other)

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun SpecializedCryptoPublicKey.equalsCryptographically(other: CryptoPublicKey) =
    toCryptoPublicKey().map { it.equalsCryptographically(other) }.getOrElse { false }

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun SpecializedCryptoPublicKey.equalsCryptographically(other: SpecializedCryptoPublicKey) =
    toCryptoPublicKey().map { other.equalsCryptographically(it) }.getOrElse { false }

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun CryptoPublicKey.equalsCryptographically(other: SpecializedCryptoPublicKey) =
    other.equalsCryptographically(this)

private const val PREFIX_DID_KEY = "did:key:"
private const val PREFIX_DID_JWK = "did:jwk:"

/** JWK members carrying private or symmetric key material (RFC 7518), which must not be present in a `did:jwk` */
private val DID_JWK_PRIVATE_MEMBERS = listOf("d", "p", "q", "dp", "dq", "qi", "oth", "k")
