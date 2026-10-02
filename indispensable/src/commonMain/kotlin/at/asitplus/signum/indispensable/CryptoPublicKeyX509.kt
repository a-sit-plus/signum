package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo.Companion.rsa
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
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

interface PublicKeyFormatProvider {
    fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey?
    fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): CryptoPublicKey?
}

fun RsaPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): RsaPublicKey =
    RsaPublicKey({
        RsaPublicKey.Content(Pkcs1RsaPublicKeyInfo.of(src))
    }, mapOf(X509 to src))

operator fun RsaPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): RsaPublicKey = fromAsn1Representation(src)

fun EcdsaPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): EcdsaPublicKey =
    EcdsaPublicKey({
        val parsed = Sec1EcPublicKeyInfo.of(src)
        val curve = ECCurve.entries.find { it.oid == parsed.curveOid }
            ?: throw Asn1Exception("Curve not supported: ${parsed.curveOid}")
        when (parsed) {
            is Sec1EcPublicKeyInfo.Compressed ->
                EcdsaPublicKey.fromCompressed(curve, parsed.x, parsed.positiveY)
            is Sec1EcPublicKeyInfo.Uncompressed ->
                EcdsaPublicKey.fromUncompressed(curve, parsed.x, parsed.y)
        }.let { EcdsaPublicKey.Content(it.publicPoint, it.preferCompressedRepresentation) }
    }, mapOf(X509 to src))

operator fun EcdsaPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): EcdsaPublicKey = fromAsn1Representation(src)
