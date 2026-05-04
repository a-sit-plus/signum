package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.Awesn1Backed
import at.asitplus.signum.indispensable.asn1.Awesn1BackedSerializer
import at.asitplus.signum.indispensable.asn1.toAsn1Integer
import at.asitplus.signum.indispensable.asn1.toBigInteger
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.max
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.internals.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


/**
 * Interface which holds Asn1 Encoding of a signature of a specified algorithm
 * Allows simple ASN1 - Raw transformation of signature values
 */

@Serializable(with = CryptoSignature.Companion::class)
sealed interface CryptoSignature {


    val backing: SignatureValue

    /**
     * Well-defined CryptoSignatures, which can also be encoded to raw bytes, in addition to the DER encoding
     * specified in the X.509 profile.
     * RSA Signatures and EC Signatures with a known curve fall into this category.
     *
     * **This is the opposite of a [NotRawByteEncodable] signature**
     */
    sealed interface RawByteEncodable : CryptoSignature {
        /**
         * Removes ASN1 Structure and returns the signature value(s) as ByteArray
         */
        val rawByteArray: ByteArray
    }

    /**
     * **This is the opposite of a [RawByteEncodable] signature**
     *
     * This inverse "non-trait" is required to group [CryptoSignature] subtypes which cannot be encoded into raw byte arrays,
     * since not all properties required to do so are known. For example, EC signatures parsed from an
     * [Certificate] do not specify a curve. For signatures obtained this way, it is impossible to know
     * how the components should be padded before encoding it into raw bytes.
     *
     * The reason this interface exists, is that it allows for grouping all such signatures in the same manner
     * as the [RawByteEncodable] ones, to allow for exhaustive `when` clauses
     *
     */
    sealed interface NotRawByteEncodable : CryptoSignature

    val humanReadableString: String
        get() = "${this::class.simpleName ?: "CryptoSignature"}(signature=${
            DER.encodeToTlv(
                this
            ).prettyPrint()
        })"

    @Serializable(with = EC.Companion::class)
    sealed class EC
    @Throws(IllegalArgumentException::class) private constructor(
        /** r - ECDSA signature component */
        val r: BigInteger,
        /** s - ECDSA signature component */
        val s: BigInteger
    ) : CryptoSignature {

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

        @Serializable(with = IndefiniteLength.Companion::class)
        class IndefiniteLength internal constructor(
            r: BigInteger, s: BigInteger
        ) : EC(r, s), Awesn1Backed<SignatureValue>, NotRawByteEncodable {
            override val backing: SignatureValue = SignatureValue.fromRS(
                r.toAsn1Integer() as Asn1Integer.Positive,
                s.toAsn1Integer() as Asn1Integer.Positive
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
            @HazardousMaterials("Risky business!")
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

            companion object :
                Awesn1BackedSerializer<SignatureValue, IndefiniteLength>(SignatureValue.serializer(), wrap = {
                    it.decodeRS().let { (r, s) ->
                        IndefiniteLength(r.toBigInteger(), s.toBigInteger())
                    }
                }) {
                private val curvesByScalarLength by lazy { ECCurve.entries.sortedBy { it.scalarLength } }
            }
        }

        class DefiniteLength @Throws(IllegalArgumentException::class) internal constructor(
            /**
             * scalar byte length of the underlying curve;
             * we do not know _which_ curve with this particular byte length
             * since raw signatures do not carry this information
             */
            val scalarByteLength: UInt,
            r: BigInteger, s: BigInteger
        ) : EC(r, s), RawByteEncodable {
            init {
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
            override val backing: SignatureValue = SignatureValue.fromRS(
                r.toAsn1Integer() as Asn1Integer.Positive,
                s.toAsn1Integer() as Asn1Integer.Positive
            )
        }

        companion object : KSerializer<EC> {

            fun fromRS(r: BigInteger, s: BigInteger) =
                EC.IndefiniteLength(r, s)

            /** load CryptoSignature from raw byte array (r and s concatenated) */
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

            override val descriptor: SerialDescriptor
                get() = PrimitiveSerialDescriptor(
                    "Signature.EC",
                    PrimitiveKind.STRING
                )

            override fun serialize(
                encoder: Encoder,
                value: EC
            ) {
                encoder.encodeSerializableValue(IndefiniteLength.serializer(), EC.IndefiniteLength(value.r, value.s))
            }

            override fun deserialize(decoder: Decoder): EC =
                decoder.decodeSerializableValue(IndefiniteLength.serializer())
        }

    }


    @Serializable(with = RSA.Companion::class)
    data class RSA(override val backing: SignatureValue) : Awesn1Backed<SignatureValue>, RawByteEncodable {
        constructor(rawBytes: ByteArray) : this(SignatureValue(rawBytes))

        /** the raw bytes of the signature value */
        override val rawByteArray get() = backing.rawBytes

        override fun toString() = humanReadableString
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RSA) return false

            if (backing != other.backing) return false

            return true
        }

        override fun hashCode(): Int {
            return backing.hashCode()
        }


        companion object : Awesn1BackedSerializer<SignatureValue, RSA>(SignatureValue.serializer(), ::RSA)

    }

    companion object : KSerializer<CryptoSignature> {
        //TODO
        override val descriptor: SerialDescriptor get() = PrimitiveSerialDescriptor("Signature", PrimitiveKind.STRING)

        override fun serialize(
            encoder: Encoder,
            value: CryptoSignature
        ) {
            when (value) {
                is EC -> encoder.encodeSerializableValue(EC.serializer(), value)
                is RSA -> encoder.encodeSerializableValue(RSA.serializer(), value)
            }
        }

        fun fromSignatureValue(signatureValue: SignatureValue): CryptoSignature=  catchingUnwrapped {
            signatureValue.decodeRS().let { (r, s) -> EC.IndefiniteLength(r.toBigInteger(), s.toBigInteger()) }
        }.getOrElse {
            RSA(signatureValue)
        }

        override fun deserialize(decoder: Decoder): CryptoSignature {
            val raw = decoder.decodeSerializableValue(SignatureValue.serializer())
            return fromSignatureValue(raw)
        }
    }
}
