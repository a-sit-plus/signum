package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.PemBlock
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.decodeFromPem
import at.asitplus.awesn1.validate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.asn1Representation
import at.asitplus.signum.indispensable.pki.invoke
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray

/** Existing certificate consumers retain their DER/PEM convenience functions. */
fun Certificate.encodeToDer(der: Der = DER): ByteArray = encode(der)

fun Certificate.encodeToTlv(der: Der = DER): Asn1Element =
    der.encodeToTlv(X509Certificate.serializer(), asn1Representation)

fun Certificate.encodeToPemBlock(der: Der = DER): PemBlock =
    PemBlock(X509Certificate.canonicalPemLabel, payload = encode(der))

fun Certificate.encodeToPem(der: Der = DER): String = encodeToPemBlock(der).encodeToPem()

fun Certificate.Companion.decodeFromDer(bytes: ByteArray, der: Der = DER): Certificate = decode(bytes, der)

fun Certificate.Companion.decodeFromTlv(src: Asn1Element, der: Der = DER): Certificate =
    Certificate(der.decodeFromTlv(X509Certificate.serializer(), src), der)

fun Certificate.Companion.decodeFromPemBlock(
    src: PemBlock, limit: Long = src.payload.size.toLong(), der: Der = DER,
): Certificate {
    X509Certificate.validate(src)
    require(!src.headers.any()) { "Unexpected PEM headers are present in the data" }
    require(src.payload.size.toLong() <= limit) { "Certificate exceeds input limit" }
    return decode(src.payload, der)
}

fun Certificate.Companion.decodeFromPem(src: String, limit: Long? = null, der: Der = DER): Certificate =
    PemBlock.decodeFromPem(src).let { decodeFromPemBlock(it, limit ?: it.payload.size.toLong(), der) }

fun Certificate.Companion.decodeFromByteArray(
    src: ByteArray, limit: Long = src.size.toLong(), der: Der = DER,
): Certificate? {
    fun decodeLimited(bytes: ByteArray): Certificate {
        require(bytes.size.toLong() <= limit) { "Certificate exceeds input limit" }
        return decode(bytes, der)
    }
    return catchingUnwrapped { decodeLimited(src) }.getOrNull()
        ?: catchingUnwrapped { decodeLimited(src.decodeToByteArray(Base64())) }.getOrNull()
        ?: decodeFromPem(src.decodeToString(), limit, der)
}
