package at.asitplus.signum.indispensable.signature

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.BitStringSignatureValue
import at.asitplus.awesn1.crypto.EcdsaSignatureValue
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.encoding.*
import at.asitplus.awesn1.runRethrowing
import at.asitplus.signum.indispensable.asn1.decodeToBigInteger
import at.asitplus.signum.indispensable.asn1.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.toAsn1Integer
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.Awesn1Backed
import at.asitplus.signum.indispensable.ec.ECCurve
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.max
import at.asitplus.signum.internals.orLazy
import at.asitplus.signum.indispensable.pki.X509Certificate
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.serializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Interface which holds Asn1 Encoding of a signature of a specified algorithm
 * Allows simple ASN1 - Raw transformation of signature values
 */
@Serializable(with = Signature.SignatureAsn1Serializer::class)
sealed interface Signature : Asn1Encodable<Asn1Element>,
    Awesn1Backed<Asn1Encodable<Asn1Element>, Asn1Element, Nothing> {

    override val raw: Asn1Encodable<Asn1Element>


        /**
         * Well-defined signatures, which can also be encoded to raw bytes, in addition to the DER encoding
         * specified in the X.509 profile.
         * RSA Signatures and EC Signatures with a known curve fall into this category.
         *
         * **This is the opposite of a [NotRawByteEncodable] signature**
         */
        sealed interface RawByteEncodable : Signature {
            /**
             * Removes ASN1 Structure and returns the signature value(s) as ByteArray
             */
            val rawByteArray: ByteArray
        }

        /**
         * **This is the opposite of a [RawByteEncodable] signature**
         *
         * This inverse "non-trait" is required to group [Signature] subtypes which cannot be encoded into raw byte arrays,
         * since not all properties required to do so are known. For example, EC signatures parsed from an
         * [X509Certificate] do not specify a curve. For signatures obtained this way, it is impossible to know
         * how the components should be padded before encoding it into raw bytes.
         *
         * The reason this interface exists, is that it allows for grouping all such signatures in the same manner
         * as the [RawByteEncodable] ones, to allow for exhaustive `when` clauses
         *
         */
        sealed interface NotRawByteEncodable : Signature

    val humanReadableString: String get() = "${this::class.simpleName ?: "Signature"}(signature=${encodeToTlv().prettyPrint()})"


    object SignatureAsn1Serializer : TransformingSerializerTemplate<Signature, SignatureValue>(
        parent = serializer<SignatureValue>(),
        encodeAs = {
            it.raw as? SignatureValue
                ?: throw IllegalArgumentException("Unsupported raw signature type ${it.raw::class.qualifiedName}")
        },
        decodeAs = Signature::fromRaw,
        serialName = "Signature",
    )


    sealed class EC
    @Throws(IllegalArgumentException::class)
    private constructor(
        final override val raw: EcdsaSignatureValue,
    ) : Signature {
        /** r - ECDSA signature component */
        val r get() = raw.r.toBigInteger()
        /** s - ECDSA signature component */
        val s get() = raw.s.toBigInteger()

        init {
            require(r.isPositive) { "r must be positive" }
            require(s.isPositive) { "s must be positive" }
        }

        /**
         * Two signatures are considered equal if `r` and `s` are equal.
         * This is true even if they are of definite length, and the lengths differ.
         *
         * We chose this approach to allow definite and indefinite length encodings of the same signature
         * to be equal, while preserving the transitivity contract of `equals`.
         */
        override fun equals(other: Any?): Boolean {
            if (other !is EC) return false
            return ((this.s == other.s) && (this.r == other.r))
        }

        override fun toString() = humanReadableString

        /** @see equals */
        override fun hashCode() = 31 * this.s.hashCode() + this.r.hashCode()

        class IndefiniteLength constructor(
            raw: EcdsaSignatureValue,
        ) : EC(raw), NotRawByteEncodable {
            constructor(r: BigInteger, s: BigInteger) : this(
                EcdsaSignatureValue(
                    r.toAsn1Integer() as Asn1Integer.Positive,
                    s.toAsn1Integer() as Asn1Integer.Positive
                )
            )

            /**
             * specifies the curve's scalar byte length for this signature, allowing it to be converted to raw bytes
             */
            fun withScalarByteLength(l: UInt) =
                EC.DefiniteLength(l, r, s)

            /**
             * specifies the curve context for this signature, allowing it to be converted to raw bytes
             */
            fun withCurve(c: ECCurve) =
                withScalarByteLength(c.scalarLength.bytes)

            /**
             * tries to guess the curve from the bit length of the indefinite-length r/s values
             * this will work well in the vast majority of cases, but may fail in pathological edge cases
             * (when r/s have a very large number of leading zeroes)
             */
            fun guessCurve(): EC.DefiniteLength {
                val minLength = max(BitLength.of(r), BitLength.of(s))
                val idx = curvesByScalarLength.binarySearchBy(minLength) { it.scalarLength }

                return withCurve(
                    when {
                        idx >= 0 -> curvesByScalarLength[idx]
                        idx >= -curvesByScalarLength.size -> curvesByScalarLength[-1 - idx]
                        else -> throw IllegalArgumentException("No curve with bit length >= $minLength is supported")
                    }
                )
            }

            companion object {
                private val curvesByScalarLength by lazy { ECCurve.entries.sortedBy { it.scalarLength } }
            }
        }

        class DefiniteLength @Throws(IllegalArgumentException::class) constructor(
            raw: EcdsaSignatureValue,
        ) : EC(raw), RawByteEncodable {
            /**
             * scalar byte length of the underlying curve;
             * we do not know _which_ curve with this particular byte length
             * since raw signatures do not carry this information
             */
            private var scalarByteLengthBacking: UInt? = null
            val scalarByteLength: UInt
                get() = requireNotNull(scalarByteLengthBacking) { "scalarByteLength is not available for this signature" }

            constructor(
                raw: EcdsaSignatureValue,
                scalarByteLength: UInt,
            ) : this(raw) {
                validateScalarByteLength(scalarByteLength)
                scalarByteLengthBacking = scalarByteLength
            }

            constructor(
                scalarByteLength: UInt,
                r: BigInteger,
                s: BigInteger,
            ) : this(
                EcdsaSignatureValue(
                    r.toAsn1Integer() as Asn1Integer.Positive,
                    s.toAsn1Integer() as Asn1Integer.Positive
                ),
                scalarByteLength
            )

            private fun validateScalarByteLength(scalarByteLength: UInt) {
                val max = scalarByteLength.toInt() * 8

                require(r.bitLength() <= max) {
                    "r is ${r.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes (${max} bits)"
                }

                require(s.bitLength() <= max) {
                    "s is ${s.bitLength()} bits long, expected at most ${scalarByteLength.toInt()} bytes (${max} bits)"
                }
            }

            /**
             * Concatenates [r] and [s], padding each one to the next largest coordinate length
             * of an [ECCurve], for use in e.g. JWS signatures.
             */
            override val rawByteArray by lazy {
                r.toByteArray().ensureSize(scalarByteLength) +
                        s.toByteArray().ensureSize(scalarByteLength)
            }
        }

        companion object : Asn1Decodable<Asn1Element, EC.IndefiniteLength> {

            fun fromRS(r: BigInteger, s: BigInteger) =
                EC.IndefiniteLength(r, s)

            /** load Signature from raw byte array (r and s concatenated) */
            @Throws(IllegalArgumentException::class)
            fun fromRawBytes(input: ByteArray): EC.DefiniteLength {
                require(input.size.rem(2) == 0) { "Raw signature has odd number of bytes" }
                val sz = input.size.div(2)
                return EC.DefiniteLength(
                    sz.toUInt(),
                    r = BigInteger.fromByteArray(input.copyOfRange(0, sz), Sign.POSITIVE),
                    s = BigInteger.fromByteArray(input.copyOfRange(sz, 2 * sz), Sign.POSITIVE)
                )
            }

            /** load from raw byte array (r and s concatenated), asserting that the size fits this particular curve */
            @Throws(IllegalArgumentException::class)
            fun fromRawBytes(curve: ECCurve, input: ByteArray): EC.DefiniteLength {
                val sz = curve.scalarLength.bytes.toInt()
                require(input.size == sz * 2)
                return fromRawBytes(input)
            }

            override fun doDecode(src: Asn1Element): EC.IndefiniteLength {
                val sequence = src.asSequence()
                if (sequence.children.size != 2) throw Asn1Exception("Illegal Signature Format")
                return IndefiniteLength(EcdsaSignatureValue.decodeFromTlv(sequence))
            }


            @Deprecated(
                "use fromRawBytes",
                ReplaceWith("Signature.EC.fromRawBytes(input)", "at.asitplus.signum.indispensable.Signature"),
                DeprecationLevel.ERROR
            )
            operator fun invoke(input: ByteArray): DefiniteLength = fromRawBytes(input)

        }

    }

    class RSA(
        override val raw: BitStringSignatureValue,
    ) : Signature, RawByteEncodable {
        constructor(rawBytes: ByteArray) : this(BitStringSignatureValue(Asn1BitString(rawBytes)))
        constructor(x509Element: Asn1Primitive) : this(BitStringSignatureValue(x509Element.asAsn1BitString()))

        /** the signature encoded as an ASN.1 BIT STRING */
        val signature: Asn1Primitive
            get() = raw.encodeToTlv()

        /** the raw bytes of the signature value */
        override val rawByteArray get() = raw.bitString.rawBytes

        override fun hashCode(): Int = signature.hashCode()

        override fun toString() = humanReadableString

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as RSA

            return signature == other.signature
        }

        companion object : Asn1Decodable<Asn1Element, RSA> {
            @Throws(Asn1Exception::class)
            override fun doDecode(src: Asn1Element): RSA {
                src as Asn1Primitive
                return RSA(src)
            }
        }
    }

    companion object : Asn1Decodable<Asn1Element, Signature> {
        fun fromRaw(raw: SignatureValue): Signature = when (raw) {
            is EcdsaSignatureValue -> EC.IndefiniteLength(raw)
            is BitStringSignatureValue -> RSA(raw)
            else -> throw IllegalArgumentException("Unsupported raw signature type ${raw::class.qualifiedName}")
        }

        @Throws(Asn1Exception::class)
        override fun doDecode(src: Asn1Element): Signature = runRethrowing {
            when (src.tag) {
                Asn1Element.Tag.BIT_STRING -> fromRaw(BitStringSignatureValue(src.asPrimitive().asAsn1BitString()))
                Asn1Element.Tag.SEQUENCE -> fromRaw(EcdsaSignatureValue.decodeFromTlv(src.asSequence()))

                else -> throw Asn1Exception("Unknown Signature Format")
            }
        }

    }
}

@Deprecated(
    "Renamed to Signature.",
    ReplaceWith("Signature", "at.asitplus.signum.indispensable.Signature")
)
typealias CryptoSignature = Signature

@Deprecated(
    "Renamed to Signature.SignatureSerializer.",
    ReplaceWith("Signature.SignatureAsn1Serializer", "at.asitplus.signum.indispensable.Signature")
)
object CryptoSignatureSerializer : KSerializer<Signature> {
    override val descriptor: SerialDescriptor get() = Signature.SignatureAsn1Serializer.descriptor

    override fun deserialize(decoder: Decoder): Signature =
        Signature.SignatureAsn1Serializer.deserialize(decoder)

    override fun serialize(encoder: Encoder, value: Signature) =
        Signature.SignatureAsn1Serializer.serialize(encoder, value)
}
