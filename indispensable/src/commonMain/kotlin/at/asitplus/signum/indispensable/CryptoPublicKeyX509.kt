package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.io.UVarInt
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey

/** Representation of the key in the format used by iOS. */
val CryptoPublicKey.iosEncoded: ByteArray
    get() = toAsn1().subjectPublicKey.also {
        require(it.numPaddingBits == 0) { "SPKI is not full octets, cannot convert to iOS" }
    }.bitCarryingBytes

interface PublicKeyFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: CryptoPublicKey): SubjectPublicKeyInfo? = null

    fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey?

    // TODO: this should be its own source format, with its own unknown wrapper, etc
    fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): CryptoPublicKey?
}

// TODO: we probably want to move this to an extension?
fun RsaPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): RsaPublicKey {
    // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    val parsed = Pkcs1RsaPublicKeyInfo.of(src, Signum.Der)
    return RsaPublicKey(
        n = parsed.modulus as Asn1Integer.Positive,
        e = parsed.publicExponent as Asn1Integer.Positive,
        // TODO: this should use the new decoder lambda stuff
    ).apply { @OptIn(SignumInternals::class) finangleSourceRepresentation(src) }
}

operator fun RsaPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): RsaPublicKey = fromAsn1Representation(src)

// TODO: we probably want to move this to an extension?
fun EcdsaPublicKey.Companion.fromAsn1Representation(src: SubjectPublicKeyInfo): EcdsaPublicKey {
    // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    val parsed = Sec1EcPublicKeyInfo.of(src, Signum.Der)
    val curve = ECCurve.entries.find { it.oid == parsed.curveOid }
        ?: throw Asn1Exception("Curve not supported: ${parsed.curveOid}")
    val key = when (parsed) {
        is Sec1EcPublicKeyInfo.Compressed -> EcdsaPublicKey.fromCompressed(curve, parsed.x, parsed.positiveY)
        is Sec1EcPublicKeyInfo.Uncompressed -> EcdsaPublicKey.fromUncompressed(curve, parsed.x, parsed.y)
    }
    return EcdsaPublicKey(key.publicPoint, key.preferCompressedRepresentation)
        // TODO: this should use the new decoder lambda stuff
        .apply { @OptIn(SignumInternals::class) finangleSourceRepresentation(src) }
}

operator fun EcdsaPublicKey.Companion.invoke(src: SubjectPublicKeyInfo): EcdsaPublicKey = fromAsn1Representation(src)
