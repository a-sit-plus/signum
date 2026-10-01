package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo.Companion.rsa
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.io.UVarInt
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey

val CryptoPublicKey.asn1Representation: SubjectPublicKeyInfo
    get() = representations[X509] as? SubjectPublicKeyInfo ?: when (this) {
        is RsaPublicKey -> SubjectPublicKeyInfo.rsa(n, e)
        is EcdsaPublicKey -> SubjectPublicKeyInfo.from(Sec1EcPublicKeyInfo.Uncompressed(curve.oid, xBytes, yBytes))
        else -> throw UnsupportedCryptoException("No X.509 representation for ${this::class.simpleName}")
    }

fun CryptoPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): CryptoPublicKey =
    ServiceLoader.load<PublicKeyFormatProvider>().get(src, PublicKeyFormatProvider::decodeFromAsn1)

operator fun CryptoPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): CryptoPublicKey =
    fromAsn1Representation(src)

/** Representation of the key in the format used by iOS. */
val CryptoPublicKey.iosEncoded: ByteArray
    get() = asn1Representation.subjectPublicKey.also {
        require(it.numPaddingBits == 0.toByte()) { "SPKI is not full octets, cannot convert to iOS" }
    }.bitCarryingBytes

// Compatibility while remaining consumers migrate to format operations.
fun CryptoPublicKey.encodeToDer(der: Der = DER) = der.encodeToByteArray(CryptoPublicKeyX509Serializer, this)
fun CryptoPublicKey.encodeToTlv(der: Der = DER) = der.encodeToTlv(CryptoPublicKeyX509Serializer, this)
fun CryptoPublicKey.encodeToPemBlock(der: Der = DER) =
    PemBlock(SubjectPublicKeyInfo.canonicalPemLabel, payload = encodeToDer(der))
fun CryptoPublicKey.encodeToPem(der: Der = DER) = encodeToPemBlock(der).encodeToPem()
fun CryptoPublicKey.Companion.decodeFromTlv(src: SubjectPublicKeyInfo, der: Der = DER) = fromAsn1Representation(src)
fun CryptoPublicKey.Companion.decodeFromTlv(src: Asn1Element, der: Der = DER) = der.decodeFromTlv(CryptoPublicKeyX509Serializer, src)
fun CryptoPublicKey.Companion.decodeFromDer(src: ByteArray, der: Der = DER) = der.decodeFromByteArray(CryptoPublicKeyX509Serializer, src)
fun CryptoPublicKey.Companion.fromSubjectPublicKeyInfo(src: SubjectPublicKeyInfo) = fromAsn1Representation(src)
fun CryptoPublicKey.Companion.decodeFromPemBlock(src: PemBlock, limit: Long = src.payload.size.toLong(), der: Der = DER): CryptoPublicKey {
    SubjectPublicKeyInfo.validate(src)
    require(!src.headers.any()) { "Unexpected PEM headers are present in the data" }
    require(src.payload.size.toLong() <= minOf(limit, der.configuration.maxInputLength)) { "Public key exceeds input limit" }
    return when (src.pemLabel) {
        Pkcs1RsaPublicKeyInfo.PEM_LABEL -> {
            val model = der.decodeFromByteArray(Pkcs1RsaPublicKeyInfo.serializer(), src.payload)
            RsaPublicKey(model.modulus, model.publicExponent)
        }
        else -> decodeFromDer(src.payload, der)
    }
}
fun CryptoPublicKey.Companion.decodeFromPem(src: String, limit: Long? = null, der: Der = DER): CryptoPublicKey =
    PemBlock.decodeFromPem(src).let { decodeFromPemBlock(it, limit ?: it.payload.size.toLong(), der) }

interface PublicKeyFormatProvider {
    fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey?
    fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): CryptoPublicKey?
}

