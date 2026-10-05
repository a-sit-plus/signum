package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.io.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey

/**
 * Representation of a public key structure
 */
interface CryptoPublicKey : Encodable {

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or Cose Keys may define an arbitrary key IDs.
     * This is not meant for Algorithm parameters! If an algorithm needs parameters, the implementing classes should be extended
     */
    //must be serializable, therefore <String,String>
    val additionalProperties: MutableMap<String, String>

    /** Representation of the key in DID format */
    val didEncoded: String get() =
        PREFIX_DID_KEY +
                (didCodec.encodeToByteArray() + didKeyBytes).multibaseEncode(MultiBase.Base.BASE58_BTC)
    val didCodec: UVarInt
    val didKeyBytes: ByteArray

    companion object : Decodable<CryptoPublicKey> {
        init { Indispensable.init() }

        /**
         * Parses a DID representation of a public key and
         * reconstructs the corresponding [CryptoPublicKey] from it
         * @throws Throwable all sorts of exception on invalid input
         */
        @Throws(Throwable::class)
        fun fromDid(input: String): CryptoPublicKey {
            val bytes = multiKeyRemovePrefix(input).substringBefore("#")
            val decoded = catching { bytes.multibaseDecode() }.getOrThrow()
                ?: throw IndexOutOfBoundsException("Unsupported multibase encoding")
            val (codec, codecLength) = UVarInt.fromByteArrayPermissive(decoded)
            val keyBytes = decoded.copyOfRange(codecLength, decoded.size)

            return ServiceLoader.load<PublicKeyFormatProvider>().get(codec) {
                decodeFromDidKey(it, keyBytes)
            }
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

@Throws(Throwable::class)
private fun multiKeyRemovePrefix(keyId: String): String =
    keyId.takeIf { it.startsWith(PREFIX_DID_KEY) }?.removePrefix(PREFIX_DID_KEY)
        ?: throw IllegalArgumentException("Input does not specify public key")
