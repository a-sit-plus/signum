package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.io.UVarInt
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Decoders
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Encoders
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import com.ionspin.kotlin.bignum.integer.Sign

/** Representation of the key in the format used by iOS. */
// TODO: this should probably be its own source format
val CryptoPublicKey.iosEncoded: ByteArray
    get() = when (this) {
        is EcdsaPublicKey -> this.toAnsiX963Encoded(useCompressed = false)
        else -> this.asn1.toRepresentation().subjectPublicKey.also {
            require(it.numPaddingBits == 0) { "SPKI is not full octets, cannot convert to iOS" }
        }.bitCarryingBytes
    }

interface Asn1PublicKeyFormatProvider {
    /** Return the ASN.1 representation, or null if this provider does not support the value. */
    fun encodeToAsn1(value: CryptoPublicKey): SubjectPublicKeyInfo? = null

    fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey?

    // TODO: this should be its own source format, with its own unknown wrapper, etc
    fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): CryptoPublicKey?
}

object RsaPublicKeyAsn1Constructors
    : Asn1EncodingHelpers.Asn1Decoders.WithPEM<SubjectPublicKeyInfo, RsaPublicKey> by
    (asn1Decoders(SubjectPublicKeyInfo.Companion) { src: SubjectPublicKeyInfo ->
        val decoded = Pkcs1RsaPublicKeyInfo.of(src, Signum.Der)
        RsaPublicKeyAsn1Constructors.invoke(decoded)
    })
{
    val PKCS1 get() = asn1Decoders(Pkcs1RsaPublicKeyInfo.Companion) { src ->
        RsaPublicKey(
            n = src.modulus as Asn1Integer.Positive,
            e = src.publicExponent as Asn1Integer.Positive,
        )
    }

    operator fun invoke(src: Pkcs1RsaPublicKeyInfo) = PKCS1(src)
}

val RsaPublicKey.Companion.fromAsn1 get() = RsaPublicKeyAsn1Constructors

class RsaPublicKeyAsn1Converters(self: RsaPublicKey) :
    Asn1EncodingHelpers.Asn1Encoders.WithPEM<SubjectPublicKeyInfo> by
    (self.asn1Encoders { SubjectPublicKeyInfo.from(convert(it), Signum.Der) })
{
    val pkcs1 = self.asn1Encoders(::convert)

    companion object {
        private fun convert(self: RsaPublicKey) = Pkcs1RsaPublicKeyInfo(self.n, self.e)
    }
}

val RsaPublicKey.asn1 get() = RsaPublicKeyAsn1Converters(this)

class EcdsaPublicKeyAsn1Converters(self: EcdsaPublicKey) :
    Asn1EncodingHelpers.Asn1Encoders.WithPEM<SubjectPublicKeyInfo> by
    (self.asn1Encoders { SubjectPublicKeyInfo.from(convert(self)) })
{

    val toSec1 = { self.encodeTo(::convert) }

    companion object {
        private fun convert(self: EcdsaPublicKey) = when (self.preferCompressedRepresentation) {
            true -> Sec1EcPublicKeyInfo.Compressed(self.curve.oid, self.xBytes, self.yCompressed == Sign.POSITIVE)
            false -> Sec1EcPublicKeyInfo.Uncompressed(self.curve.oid, self.xBytes, self.yBytes)
        }
    }
}

val EcdsaPublicKey.asn1 get() = EcdsaPublicKeyAsn1Converters(this)

object EcdsaPublicKeyAsn1Constructors :
    Asn1EncodingHelpers.Asn1Decoders.WithPEM<SubjectPublicKeyInfo, EcdsaPublicKey> by
    (asn1Decoders(SubjectPublicKeyInfo.Companion) { src: SubjectPublicKeyInfo ->
        EcdsaPublicKey.fromAsn1.SEC1(Sec1EcPublicKeyInfo.of(src, Signum.Der))
    })
{
    val SEC1 get() = decodeFrom { parsed: Sec1EcPublicKeyInfo ->
        val curve = ECCurve.entries.find { it.oid == parsed.curveOid }
            ?: throw Asn1Exception("Curve not supported: ${parsed.curveOid}")
        val key = when (parsed) {
            is Sec1EcPublicKeyInfo.Compressed -> EcdsaPublicKey.fromCompressed(curve, parsed.x, parsed.positiveY)
            is Sec1EcPublicKeyInfo.Uncompressed -> EcdsaPublicKey.fromUncompressed(curve, parsed.x, parsed.y)
        }
        EcdsaPublicKey(key.publicPoint, key.preferCompressedRepresentation)
    }

    operator fun invoke(sec1: Sec1EcPublicKeyInfo) = SEC1(sec1)
}

val EcdsaPublicKey.Companion.fromAsn1 get() = EcdsaPublicKeyAsn1Constructors
