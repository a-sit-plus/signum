package at.asitplus.signum.indispensable

import at.asitplus.KmmResult
import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.catching
import at.asitplus.io.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import kotlinx.serialization.KSerializer

// @ServiceProvider
interface PublicKeyFormatProvider {
    fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey?
    fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): CryptoPublicKey?
}

/**
 * Representation of a public key structure
 */
abstract class CryptoPublicKey : DerPemEncodable<SubjectPublicKeyInfo>, Identifiable {

    /**
     * This is meant for storing additional properties, which may be relevant for certain use cases.
     * For example, Json Web Keys or Cose Keys may define an arbitrary key IDs.
     * This is not meant for Algorithm parameters! If an algorithm needs parameters, the implementing classes should be extended
     */
    //must be serializable, therefore <String,String>
    val additionalProperties = mutableMapOf<String, String>()

    /** Representation of the key in DID format */
    val didEncoded: String by lazy {
        PREFIX_DID_KEY +
                (didCodec.encodeToByteArray() + didKeyBytes).multibaseEncode(MultiBase.Base.BASE58_BTC)
    }
    abstract val didCodec: UVarInt
    abstract val didKeyBytes: ByteArray

    /** Representation of the key in the format used by iOS */
    open val iosEncoded: ByteArray get() = asn1Representation.subjectPublicKey.also {
        require (it.numPaddingBits != 0.toByte()) { "SPKI is not full octets, cannot convert to iOS" }
    }.bitCarryingBytes

    fun encodeToTlv(): Asn1Sequence =
        DER.encodeToTlv(asn1Representation) as Asn1Sequence

    override val pemLabel: String get() = canonicalPemLabel

    companion object : DerPemDecodable<SubjectPublicKeyInfo, CryptoPublicKey> {
        init { Indispensable.init() }
        override val canonicalPemLabel: String get() = SubjectPublicKeyInfo.canonicalPemLabel
        override val alternativePemLabels: Set<String> get() = SubjectPublicKeyInfo.alternativePemLabels

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

        operator fun invoke(asn1Representation: SubjectPublicKeyInfo) =
            ServiceLoader.load<PublicKeyFormatProvider>()
                .get(asn1Representation, PublicKeyFormatProvider::decodeFromAsn1)

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            element: SubjectPublicKeyInfo,
            der: Der,
        ): CryptoPublicKey = CryptoPublicKey(element)

        override fun decodeFromPemBlockPayload(
            serializer: KSerializer<SubjectPublicKeyInfo>,
            src: PemBlock,
            limit: Long,
            der: Der,
        ): CryptoPublicKey =
            when (src.pemLabel) {
                Pkcs1RsaPublicKeyInfo.PEM_LABEL -> RSAPublicKey.fromPKCS1encoded(src.payload)
                else -> decodeFromDer(serializer, src.payload, limit, der)
            }

        @Throws(Asn1Exception::class)
        fun decodeFromDer(src: ByteArray): CryptoPublicKey =
            decodeFromTlv(Asn1Element.parse(src))

        @Throws(Asn1Exception::class)
        fun doDecode(src: Asn1Sequence): CryptoPublicKey =
            decodeFromTlv(src)

        fun fromSubjectPublicKeyInfo(spki: SubjectPublicKeyInfo) = CryptoPublicKey(spki)
    }

    @Deprecated(message = "Public key types migrated out of CryptoPublicKey as part of providerization",
        replaceWith = ReplaceWith("ECDSAPublicKey"))
    typealias EC = ECDSAPublicKey
    @Deprecated(message = "Public key types migrated out of CryptoPublicKey as part of providerization",
        replaceWith = ReplaceWith("RSAPublicKey"))
    typealias RSA = RSAPublicKey
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
