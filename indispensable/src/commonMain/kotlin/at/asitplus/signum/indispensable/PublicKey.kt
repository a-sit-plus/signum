package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.io.MultiBase
import at.asitplus.io.UVarInt
import at.asitplus.io.multibaseDecode
import at.asitplus.io.multibaseEncode
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey

/**
 * Representation of a public key structure
 */
interface PublicKey : WithSourceRepresentation {

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

    @SignumInternals
    class Unknown internal constructor(
        source: SubjectPublicKeyInfo,
        lookupResult: UnsupportedCryptoException,
    ) : PublicKey, ServiceLoader.UnknownShim(source, lookupResult) {
        override val didKeyBytes get() = fails
        override val didCodec get() = fails
        override val additionalProperties: MutableMap<String, String> get() = fails
    }

    companion object {
        init { Signum.installIndispensable() }

        /**
         * Parses a DID representation of a public key and
         * reconstructs the corresponding [PublicKey] from it
         * @throws Throwable all sorts of exception on invalid input
         */
        @Throws(Throwable::class)
        fun fromDid(input: String): PublicKey {
            val bytes = multiKeyRemovePrefix(input).substringBefore("#")
            val decoded = bytes.multibaseDecode()
                ?: throw IndexOutOfBoundsException("Unsupported multibase encoding")
            val (codec, codecLength) = UVarInt.fromByteArrayPermissive(decoded)
            val keyBytes = decoded.copyOfRange(codecLength, decoded.size)

            return ServiceLoader.load<Asn1PublicKeyFormatProvider>().get(codec) {
                decodeFromDidKey(it, keyBytes)
            }
        }

    }

    @Deprecated(message = "Public key types migrated out of PublicKey as part of providerization",
        replaceWith = ReplaceWith("EcdsaPublicKey"))
    typealias EC = EcdsaPublicKey
    @Deprecated(message = "Public key types migrated out of PublicKey as part of providerization",
        replaceWith = ReplaceWith("RsaPublicKey"))
    typealias RSA = RsaPublicKey
}

interface SpecializedPublicKey {
    /** Returns the public key, throwing when parameters are missing, invalid, or unsupported. */
    @Throws(Throwable::class)
    fun toPublicKey(): PublicKey

    @Deprecated("Renamed to toPublicKey", ReplaceWith("toPublicKey()"))
    @Throws(Throwable::class)
    fun toCryptoPublicKey(): PublicKey = toPublicKey()
}

/** Alias of [equals] provided for convenience (and alignment with [SpecializedPublicKey]) */
fun PublicKey.equalsCryptographically(other: PublicKey) =
    equals(other)

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun SpecializedPublicKey.equalsCryptographically(other: PublicKey) =
    catchingUnwrapped { toPublicKey() }.getOrNull()?.equalsCryptographically(other) ?: false

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun SpecializedPublicKey.equalsCryptographically(other: SpecializedPublicKey) =
    catchingUnwrapped { toPublicKey() }.getOrNull()?.let { other.equalsCryptographically(it) } ?: false

/** Whether the actual underlying key (irrespective of any format-specific metadata) is equal */
fun PublicKey.equalsCryptographically(other: SpecializedPublicKey) =
    other.equalsCryptographically(this)

private const val PREFIX_DID_KEY = "did:key:"

@Throws(Throwable::class)
private fun multiKeyRemovePrefix(keyId: String): String =
    keyId.takeIf { it.startsWith(PREFIX_DID_KEY) }?.removePrefix(PREFIX_DID_KEY)
        ?: throw IllegalArgumentException("Input does not specify public key")

@Deprecated("Renamed to PublicKey", ReplaceWith("PublicKey", "at.asitplus.signum.indispensable.PublicKey"))
typealias CryptoPublicKey = PublicKey

@Deprecated("Renamed to SpecializedPublicKey", ReplaceWith("SpecializedPublicKey", "at.asitplus.signum.indispensable.SpecializedPublicKey"))
typealias SpecializedCryptoPublicKey = SpecializedPublicKey
