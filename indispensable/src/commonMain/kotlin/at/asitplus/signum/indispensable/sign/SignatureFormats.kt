package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.crypto.EcdsaSigValue
import at.asitplus.awesn1.crypto.EcdsaSigValue.Companion.toEcdsaSigValue
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.ecdsaWithSHA1
import at.asitplus.awesn1.ecdsaWithSHA256
import at.asitplus.awesn1.ecdsaWithSHA384
import at.asitplus.awesn1.ecdsaWithSHA512
import at.asitplus.awesn1.rsaPSS
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.sha1WithRSAEncryption
import at.asitplus.awesn1.sha256WithRSAEncryption
import at.asitplus.awesn1.sha384WithRSAEncryption
import at.asitplus.awesn1.sha512WithRSAEncryption
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.awesn1.toBigInteger
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.SignatureFormatProvider
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.max
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.internals.orLazy
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlin.getValue

private data class EcSignatureContent(
    val r: BigInteger,
    val s: BigInteger,
) {
    init {
        require(r.isPositive) { "r must be positive" }
        require(s.isPositive) { "s must be positive" }
    }
}

sealed class ECDSASignature
@Throws(IllegalArgumentException::class) private constructor(
    providedContent: EcSignatureContent?,
    private val providedAsn1Representation: X509SignatureValue?,
) : CryptoSignature {

    private val content: EcSignatureContent by providedContent orLazy {
        providedAsn1Representation!!.toEcdsaSigValue()
            .let { (r,s) -> EcSignatureContent(r.toBigInteger(), s.toBigInteger()) }
    }

    val r: BigInteger get() = content.r

    val s: BigInteger get() = content.s

    override val asn1Representation: X509SignatureValue by providedAsn1Representation orLazy {
        EcdsaSigValue(r.toAsn1Integer(), s.toAsn1Integer()).toX509SignatureValue()
    }

    override fun equals(other: Any?): Boolean {
        if (other !is ECDSASignature) return false
        return s == other.s && r == other.r
    }

    override fun toString() = humanReadableString

    override fun hashCode() = 31 * s.hashCode() + r.hashCode()

    class IndefiniteLength private constructor(
        providedContent: EcSignatureContent?,
        providedAsn1Representation: X509SignatureValue?,
    ) : ECDSASignature(providedContent, providedAsn1Representation) {

        internal constructor(r: BigInteger, s: BigInteger) : this(EcSignatureContent(r, s), null)

        internal constructor(asn1Representation: X509SignatureValue) : this(null, asn1Representation)

        fun withScalarByteLength(l: UInt) =
            DefiniteLength(l, r, s)

        fun withCurve(c: ECCurve) =
            withScalarByteLength(c.scalarLength.bytes)

        fun guessCurve(): DefiniteLength {
            val minLength = max(BitLength.of(r), BitLength.of(s))
            val idx = curvesByScalarLength.binarySearchBy(minLength) { it.scalarLength }

            return withCurve(
                when {
                    idx >= 0 -> curvesByScalarLength[idx]
                    idx >= -curvesByScalarLength.size -> curvesByScalarLength[-1 - idx]
                    else -> throw IllegalArgumentException("No curve with bit length >= $minLength is supported")
                },
            )
        }

        override val joseBytes: ByteArray
            get() = throw UnsupportedCryptoException("Cannot convert indefinite length ECDSA signature to COSE/JOSE")

        companion object : DerDecodable<X509SignatureValue, IndefiniteLength> {
            override fun decodeFromTlv(
                element: X509SignatureValue,
                der: Der
            ): IndefiniteLength = ECDSASignature.decodeFromTlv(element, der)

            private val curvesByScalarLength by lazy { ECCurve.entries.sortedBy { it.scalarLength } }
        }
    }

    class DefiniteLength @Throws(IllegalArgumentException::class) internal constructor(
        val scalarByteLength: UInt,
        r: BigInteger,
        s: BigInteger,
    ) : ECDSASignature(EcSignatureContent(r, s), null) {
        init {
            val max = scalarByteLength.toInt() * 8

            require(r.bitLength() <= max) {
                "r is ${r.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes ($max bits)"
            }

            require(s.bitLength() <= max) {
                "s is ${s.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes ($max bits)"
            }
        }

        val p1363Bytes by lazy {
            r.toByteArray().ensureSize(scalarByteLength) +
                    s.toByteArray().ensureSize(scalarByteLength)
        }

        override val joseBytes get() = p1363Bytes
    }

    companion object : DerDecodable<X509SignatureValue, IndefiniteLength> {

        fun fromRS(r: BigInteger, s: BigInteger) =
            IndefiniteLength(r, s)

        @Throws(IllegalArgumentException::class)
        fun fromP1363Bytes(sigBytes: ByteArray): DefiniteLength {
            require(sigBytes.size.rem(2) == 0) { "Raw signature has odd number of bytes" }
            val sz = sigBytes.size.div(2)
            return DefiniteLength(
                sz.toUInt(),
                r = BigInteger.fromByteArray(sigBytes.copyOfRange(0, sz), Sign.POSITIVE),
                s = BigInteger.fromByteArray(sigBytes.copyOfRange(sz, 2 * sz), Sign.POSITIVE),
            )
        }

        @Deprecated("renamed", replaceWith = ReplaceWith("fromP1363Bytes(input)"))
        fun fromRawBytes(input: ByteArray) = fromP1363Bytes(input)

        fun fromP1363Bytes(curve: ECCurve, input: ByteArray): DefiniteLength {
            val sz = curve.scalarLength.bytes.toInt()
            require(input.size == sz * 2)
            return fromP1363Bytes(input)
        }

        @Throws(IllegalArgumentException::class)
        @Deprecated("renamed", replaceWith = ReplaceWith("fromP1363Bytes(curve, input)"))
        fun fromRawBytes(curve: ECCurve, input: ByteArray) = fromP1363Bytes(curve, input)

        fun fromRawSignatureValue(sigBytes: ByteArray) =
            decodeFromTlv(X509SignatureValue(sigBytes))

        /** Parses a signature produced by the JCA digestwithECDSA algorithm. */
        @Deprecated("Renamed", replaceWith = ReplaceWith("fromRawSignatureValue(input)"))
        fun parseFromJca(input: ByteArray) =
            fromRawSignatureValue(input)

        /** Parses a signature produced by the JCA digestWithECDSAinP1363Format algorithm. */
        @Deprecated("Renamed", replaceWith = ReplaceWith("fromP1363Bytes(input)"))
        fun parseFromJcaP1363(input: ByteArray) =
            fromP1363Bytes(input)

        override fun decodeFromTlv(element: X509SignatureValue, der: Der): IndefiniteLength =
            IndefiniteLength(element)

    }
}

class RSASignature private constructor(
    providedRawBytes: ByteArray?,
    providedAsn1Representation: X509SignatureValue?,
) : CryptoSignature {
    constructor(rawBytes: ByteArray) : this(rawBytes, null)

    override val asn1Representation: X509SignatureValue by providedAsn1Representation orLazy {
        X509SignatureValue(rawBytes)
    }

    val rawBytes: ByteArray by providedRawBytes orLazy {
        asn1Representation.rawBytes
    }

    override val joseBytes get() = rawBytes

    override fun hashCode(): Int = rawBytes.contentHashCode()

    override fun toString() = humanReadableString

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is RSASignature) return false
        return rawBytes.contentEquals(other.rawBytes)
    }

    companion object : DerDecodable<X509SignatureValue, RSASignature> {
        override fun decodeFromTlv(element: X509SignatureValue, der: Der): RSASignature =
            RSASignature(null, element)
        fun fromRawSignatureValue(input: ByteArray) = RSASignature(input)
        @Deprecated("Renamed", replaceWith = ReplaceWith("fromRawSignatureValue(input)"))
        fun parseFromJca(input: ByteArray) = fromRawSignatureValue(input)
    }
}

object IndispensableSignatureFormats : SignatureFormatProvider {
    override fun parseCryptoSignature(signatureAlgorithm: SignatureAlgorithm, signature: X509SignatureValue) = when (signatureAlgorithm) {
        is ECDSAAlgorithm -> {
            val parsedSig = ECDSASignature.decodeFromTlv(signature)
            when (val crv = signatureAlgorithm.requiredCurve) {
                null -> parsedSig
                else -> parsedSig.withCurve(crv)
            }
        }
        is RSAAlgorithm -> RSASignature.decodeFromTlv(signature)
        else -> null
    }

    override fun parseCryptoSignature(x509Algorithm: X509AlgorithmIdentifier, signature: X509SignatureValue) =
        when (x509Algorithm.oid) {

            KnownOIDs.sha1WithRSAEncryption, KnownOIDs.sha256WithRSAEncryption, KnownOIDs.sha384WithRSAEncryption,
            KnownOIDs.sha512WithRSAEncryption, KnownOIDs.rsaPSS
                -> RSASignature.decodeFromTlv(signature)

            KnownOIDs.ecdsaWithSHA1, KnownOIDs.ecdsaWithSHA256, KnownOIDs.ecdsaWithSHA384, KnownOIDs.ecdsaWithSHA512
                -> ECDSASignature.decodeFromTlv(signature)

            else -> null
        }
}
