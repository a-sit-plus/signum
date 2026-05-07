package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.decodeToBigInteger
import at.asitplus.awesn1.decodeRethrowing
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.encoding.decodeFromDer
import at.asitplus.awesn1.encoding.encodeToDer
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.awesn1.toBigInteger
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.max
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.internals.orLazy
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Algorithm-agnostic signature value. X.509 algorithm context lives in [X509Signature].
 */
@Serializable(with = CryptoSignature.CryptoSignatureSerializer::class)
sealed interface CryptoSignature : Asn1Encodable<Asn1Element> {

    val asn1Representation: SignatureValue

    /**
     * Well-defined signatures that can be encoded into raw bytes.
     */
    sealed interface RawByteEncodable : CryptoSignature {
        val rawByteArray: ByteArray
    }

    /**
     * Signatures that cannot be encoded into raw bytes without additional algorithm context.
     */
    sealed interface NotRawByteEncodable : CryptoSignature

    val humanReadableString: String get() = "${this::class.simpleName ?: "CryptoSignature"}(signature=${encodeToTlv().prettyPrint()})"

    object CryptoSignatureSerializer : KSerializer<CryptoSignature> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("CryptoSignature", PrimitiveKind.STRING)

        override fun deserialize(decoder: Decoder): CryptoSignature =
            CryptoSignature.decodeFromDer(decoder.decodeString().decodeToByteArray(Base64Strict))

        override fun serialize(encoder: Encoder, value: CryptoSignature) {
            encoder.encodeString(value.encodeToDer().encodeToString(Base64Strict))
        }
    }

    sealed class EC
    @Throws(IllegalArgumentException::class) private constructor(
        val r: BigInteger,
        val s: BigInteger,
    ) : CryptoSignature {

        init {
            require(r.isPositive) { "r must be positive" }
            require(s.isPositive) { "s must be positive" }
        }

        override val asn1Representation: SignatureValue by lazy {
            SignatureValue.fromRS(
                r.toAsn1Integer() as Asn1Integer.Positive,
                s.toAsn1Integer() as Asn1Integer.Positive,
            )
        }

        override fun encodeToTlv(): Asn1Element =
            Asn1Element.parse(asn1Representation.rawBytes)

        override fun equals(other: Any?): Boolean {
            if (other !is EC) return false
            return s == other.s && r == other.r
        }

        override fun toString() = humanReadableString

        override fun hashCode() = 31 * s.hashCode() + r.hashCode()

        class IndefiniteLength internal constructor(
            r: BigInteger,
            s: BigInteger,
        ) : EC(r, s), NotRawByteEncodable {

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

            companion object {
                private val curvesByScalarLength by lazy { ECCurve.entries.sortedBy { it.scalarLength } }
            }
        }

        class DefiniteLength @Throws(IllegalArgumentException::class) internal constructor(
            val scalarByteLength: UInt,
            r: BigInteger,
            s: BigInteger,
        ) : EC(r, s), RawByteEncodable {
            init {
                val max = scalarByteLength.toInt() * 8

                require(r.bitLength() <= max) {
                    "r is ${r.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes ($max bits)"
                }

                require(s.bitLength() <= max) {
                    "s is ${s.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes ($max bits)"
                }
            }

            override val rawByteArray by lazy {
                r.toByteArray().ensureSize(scalarByteLength) +
                    s.toByteArray().ensureSize(scalarByteLength)
            }
        }

        companion object : Asn1Decodable<Asn1Element, IndefiniteLength> {

            fun fromRS(r: BigInteger, s: BigInteger) =
                IndefiniteLength(r, s)

            @Throws(IllegalArgumentException::class)
            fun fromRawBytes(input: ByteArray): DefiniteLength {
                require(input.size.rem(2) == 0) { "Raw signature has odd number of bytes" }
                val sz = input.size.div(2)
                return DefiniteLength(
                    sz.toUInt(),
                    r = BigInteger.fromByteArray(input.copyOfRange(0, sz), Sign.POSITIVE),
                    s = BigInteger.fromByteArray(input.copyOfRange(sz, 2 * sz), Sign.POSITIVE),
                )
            }

            @Throws(IllegalArgumentException::class)
            fun fromRawBytes(curve: ECCurve, input: ByteArray): DefiniteLength {
                val sz = curve.scalarLength.bytes.toInt()
                require(input.size == sz * 2)
                return fromRawBytes(input)
            }

            fun fromSignatureValue(signatureValue: SignatureValue): IndefiniteLength =
                signatureValue.decodeRS().let { (r, s) -> fromRS(r.toBigInteger(), s.toBigInteger()) }

            override fun doDecode(src: Asn1Element) = src.asSequence().decodeRethrowing {
                val r = next().asPrimitive().decodeToBigInteger()
                val s = next().asPrimitive().decodeToBigInteger()
                if (hasNext()) throw Asn1Exception("Illegal Signature Format")
                fromRS(r, s)
            }

            @Deprecated(
                "use fromRawBytes",
                ReplaceWith("CryptoSignature.EC.fromRawBytes(input)"),
                DeprecationLevel.ERROR,
            )
            operator fun invoke(input: ByteArray): DefiniteLength = fromRawBytes(input)
        }
    }

    class RSA private constructor(
        providedRawBytes: ByteArray?,
        providedAsn1Representation: SignatureValue?,
    ) : CryptoSignature, RawByteEncodable {
        constructor(rawBytes: ByteArray) : this(rawBytes, null)
        constructor(x509Element: Asn1Primitive) : this(null, SignatureValue(x509Element.asAsn1BitString()))
        constructor(signatureValue: SignatureValue) : this(null, signatureValue)

        override val asn1Representation: SignatureValue by providedAsn1Representation orLazy {
            SignatureValue(rawByteArray)
        }

        val signature: Asn1Primitive by lazy {
            asn1Representation.rawBitString.encodeToTlv()
        }

        override fun encodeToTlv(): Asn1Element = signature

        override val rawByteArray: ByteArray by providedRawBytes orLazy {
            asn1Representation.rawBytes
        }

        override fun hashCode(): Int = rawByteArray.contentHashCode()

        override fun toString() = humanReadableString

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RSA) return false
            return rawByteArray.contentEquals(other.rawByteArray)
        }

        companion object : Asn1Decodable<Asn1Element, RSA> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Element): RSA =
                RSA(src.asPrimitive())
        }
    }

    companion object : Asn1Decodable<Asn1Element, CryptoSignature> {
        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Element): CryptoSignature = runRethrowing {
            when (src.tag) {
                Asn1Element.Tag.BIT_STRING -> RSA.decodeFromTlv(src)
                Asn1Element.Tag.SEQUENCE -> EC.decodeFromTlv(src)
                else -> throw Asn1Exception("Unknown Signature Format")
            }
        }

        fun fromSignatureValue(signatureValue: SignatureValue): CryptoSignature =
            catchingUnwrapped { EC.fromSignatureValue(signatureValue) }
                .getOrElse { RSA(signatureValue) }
    }
}

val CryptoSignature.x509Encoded: Asn1Primitive
    get() = asn1Representation.rawBitString.encodeToTlv()
