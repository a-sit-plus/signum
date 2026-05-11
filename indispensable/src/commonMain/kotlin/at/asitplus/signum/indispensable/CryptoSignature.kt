package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.SignatureValue
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.serialization.Der
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.max
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.internals.orLazy
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToByteArray

private data class EcSignatureContent(
    val r: BigInteger,
    val s: BigInteger,
) {
    init {
        require(r.isPositive) { "r must be positive" }
        require(s.isPositive) { "s must be positive" }
    }
}

/**
 * Algorithm-agnostic signature value. X.509 algorithm context lives in [X509Signature].
 */
sealed interface CryptoSignature : DerEncodable<SignatureValue> {

    override val asn1Representation: SignatureValue

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


    sealed class EC
    @Throws(IllegalArgumentException::class) private constructor(
        providedContent: EcSignatureContent?,
        private val providedAsn1Representation: SignatureValue?,
    ) : CryptoSignature {

        private val content: EcSignatureContent by providedContent orLazy {
            providedAsn1Representation!!.decodeRS().let { (r, s) ->
                EcSignatureContent(r.toBigInteger(), s.toBigInteger())
            }
        }

        val r: BigInteger get() = content.r

        val s: BigInteger get() = content.s

        override val asn1Representation: SignatureValue by providedAsn1Representation orLazy {
            SignatureValue.fromRS(
                r.toAsn1Integer() as Asn1Integer.Positive,
                s.toAsn1Integer() as Asn1Integer.Positive,
            )
        }

        override fun equals(other: Any?): Boolean {
            if (other !is EC) return false
            return s == other.s && r == other.r
        }

        override fun toString() = humanReadableString

        override fun hashCode() = 31 * s.hashCode() + r.hashCode()

        class IndefiniteLength private constructor(
            providedContent: EcSignatureContent?,
            providedAsn1Representation: SignatureValue?,
        ) : EC(providedContent, providedAsn1Representation), NotRawByteEncodable {

            internal constructor(r: BigInteger, s: BigInteger) : this(EcSignatureContent(r, s), null)

            internal constructor(asn1Representation: SignatureValue) : this(null, asn1Representation)

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

            companion object : DerDecodable<SignatureValue, IndefiniteLength> {
                override fun decodeFromTlv(
                    serializer: KSerializer<SignatureValue>,
                    src: Asn1Element,
                    der: Der
                ): IndefiniteLength = EC.decodeFromTlv(serializer, src, der)

                private val curvesByScalarLength by lazy { ECCurve.entries.sortedBy { it.scalarLength } }
            }
        }

        class DefiniteLength @Throws(IllegalArgumentException::class) internal constructor(
            val scalarByteLength: UInt,
            r: BigInteger,
            s: BigInteger,
        ) : EC(EcSignatureContent(r, s), null), RawByteEncodable {
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

        companion object : DerDecodable<SignatureValue, IndefiniteLength> {

            operator fun invoke(asn1Representation: SignatureValue) =
                IndefiniteLength(asn1Representation)

            //TODO: do we still want this?
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

            @Deprecated(
                "use fromRawBytes",
                ReplaceWith("CryptoSignature.EC.fromRawBytes(input)"),
                DeprecationLevel.ERROR,
            )
            operator fun invoke(input: ByteArray): DefiniteLength = fromRawBytes(input)
            override fun decodeFromTlv(
                serializer: KSerializer<SignatureValue>,
                src: Asn1Element,
                der: Der
            ): IndefiniteLength =
                IndefiniteLength(
                    der.decodeFromTlv(
                        serializer,   /*we should cater to JCA, and allow base EC signatures*/
                        if (src is Asn1Sequence) Asn1BitString(der.encodeToByteArray(src)).encodeToTlv() else src
                    )
                )

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

        companion object : DerDecodable<SignatureValue, RSA> {
            override fun decodeFromTlv(
                serializer: KSerializer<SignatureValue>,
                src: Asn1Element,
                der: Der
            ) = RSA(/*cannot really be sanity-checked*/der.decodeFromTlv(serializer, src))

        }
    }

    companion object {
        operator fun invoke(algorithmObjectIdentifier: ObjectIdentifier, asn1Representation: SignatureValue) =
            CryptoSignature(SignatureAlgorithm.kindByOID(algorithmObjectIdentifier), asn1Representation)

        operator fun invoke(kind: SignatureAlgorithm.Kind, asn1Representation: SignatureValue) =
            when (kind) {
                SignatureAlgorithm.Kind.EC -> EC(asn1Representation)
                SignatureAlgorithm.Kind.RSA -> RSA(asn1Representation)
            }
    }
}


/**
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
val CryptoSignature.jcaSignatureBytes: ByteArray
    get() = when (this) {
        is CryptoSignature.EC -> asn1Representation.rawBytes
        is CryptoSignature.RSA -> rawByteArray
    }

/**
 * In Java EC signatures are returned as DER-encoded, RSA signatures however are raw bytearrays
 */
fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SignatureAlgorithm
): CryptoSignature =
    if (algorithm is SignatureAlgorithm.ECDSA)
        CryptoSignature.EC.parseFromJca(input)
    else
        CryptoSignature.RSA.parseFromJca(input)

fun CryptoSignature.Companion.parseFromJca(
    input: ByteArray,
    algorithm: SpecializedSignatureAlgorithm
) = parseFromJca(input, algorithm.algorithm)

/**
 * Parses a signature produced by the JCA digestwithECDSA algorithm.
 */
fun CryptoSignature.EC.Companion.parseFromJca(input: ByteArray) =
    CryptoSignature.EC(SignatureValue(input))

/**
 * Parses a signature produced by the JCA digestWithECDSAinP1363Format algorithm.
 */
fun CryptoSignature.EC.Companion.parseFromJcaP1363(input: ByteArray) =
    CryptoSignature.EC.fromRawBytes(input)

fun CryptoSignature.RSA.Companion.parseFromJca(input: ByteArray) =
    CryptoSignature.RSA(input)


val CryptoSignature.iosEncoded
    get() = when (this) {
        is CryptoSignature.EC -> this.asn1Representation.rawBytes
        is CryptoSignature.RSA -> this.rawByteArray
    }
