package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.io.UVarInt
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey

val CryptoPublicKey.asn1Representation: SubjectPublicKeyInfo
    get() = representations[X509] as? SubjectPublicKeyInfo ?: run {
        Signum.installIndispensable()
        Signum.load<PublicKeyFormatProvider>().get(this, PublicKeyFormatProvider::encodeToAsn1)
    }

fun CryptoPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): CryptoPublicKey =
    Signum.load<PublicKeyFormatProvider>().get(src, PublicKeyFormatProvider::decodeFromAsn1)

operator fun CryptoPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): CryptoPublicKey =
    fromAsn1Representation(src)

/** Representation of the key in the format used by iOS. */
val CryptoPublicKey.iosEncoded: ByteArray
    get() = asn1Representation.subjectPublicKey.also {
        require(it.numPaddingBits == 0.toByte()) { "SPKI is not full octets, cannot convert to iOS" }
    }.bitCarryingBytes

interface PublicKeyFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: CryptoPublicKey): SubjectPublicKeyInfo? = null

    fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey?
    fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): CryptoPublicKey?
}

fun RsaPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): RsaPublicKey {
    // Shared nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    val parsed by lazy { Pkcs1RsaPublicKeyInfo.of(src, Signum.Der) }
    return RsaPublicKey(
        nProvider = { parsed.modulus as Asn1Integer.Positive },
        eProvider = { parsed.publicExponent as Asn1Integer.Positive },
        representations = mapOf(X509 to src),
    )
}

operator fun RsaPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): RsaPublicKey = fromAsn1Representation(src)

fun EcdsaPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): EcdsaPublicKey {
    // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    val parsed by lazy { Sec1EcPublicKeyInfo.of(src, Signum.Der) }
    return EcdsaPublicKey(
        publicPointProvider = {
            val curve = ECCurve.entries.find { it.oid == parsed.curveOid }
                ?: throw Asn1Exception("Curve not supported: ${parsed.curveOid}")
            when (val point = parsed) {
                is Sec1EcPublicKeyInfo.Compressed ->
                    EcdsaPublicKey.fromCompressed(curve, point.x, point.positiveY)
                is Sec1EcPublicKeyInfo.Uncompressed ->
                    EcdsaPublicKey.fromUncompressed(curve, point.x, point.y)
            }.publicPoint
        },
        preferCompressedRepresentationProvider = { parsed is Sec1EcPublicKeyInfo.Compressed },
        representations = mapOf(X509 to src),
    )
}

operator fun EcdsaPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): EcdsaPublicKey = fromAsn1Representation(src)
