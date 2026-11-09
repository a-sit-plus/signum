package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.agree.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.internals.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

class RsaPrivateKey(
    private val parameters: Parameters,
    override val attributes: Set<Asn1Element>? = null,
) : CryptoPrivateKey, CryptoPrivateKey.WithPublicKey {
    @SignumInternals
    override val sourceRepresentation = SourceRepresentationStorage()

    /** The RSA components form one unit: every semantic access requires valid CRT relationships. */
    data class Parameters(
        val publicKey: RsaPublicKey,
        val privateKey: BigInteger,
        val prime1: BigInteger,
        val prime2: BigInteger,
        val prime1exponent: BigInteger,
        val prime2exponent: BigInteger,
        val crtCoefficient: BigInteger,
        val otherPrimeInfos: List<PrimeInfo>?,
    ) {
        init {
            val n = publicKey.n.toBigInteger()
            val e = publicKey.e.toBigInteger()
            val primeInfo1 =
                RsaPrivateKey.PrimeInfo(prime = prime2, exponent = prime2exponent, coefficient = BigInteger.ONE)
            val primeInfo2 =
                RsaPrivateKey.PrimeInfo(prime = prime1, exponent = prime1exponent, coefficient = crtCoefficient)

            var product = BigInteger.ONE
            (sequenceOf(primeInfo1, primeInfo2) + (otherPrimeInfos?.asSequence() ?: sequenceOf()))
                .forEachIndexed { i, info ->
                    val pminusone = info.prime - BigInteger.ONE
                    require(product.times(info.coefficient).mod(info.prime) == BigInteger.ONE) {
                        "t_$i != (r_0 * ... * r_${i - 1})^(-1) mod r_$i"
                    }
                    product *= info.prime
                    require(info.exponent == privateKey.mod(pminusone)) { "d_$i != d mod (p_$i - 1)" }
                    require(e.multiply(info.exponent).mod(pminusone) == BigInteger.ONE)
                }
            require(product == n) { "p1 * p2 * ... * pk != n" }
        }
    }

    constructor(
        publicKey: RsaPublicKey,
        privateKey: BigInteger,
        prime1: BigInteger,
        prime2: BigInteger,
        prime1exponent: BigInteger,
        prime2exponent: BigInteger,
        crtCoefficient: BigInteger,
        otherPrimeInfos: List<PrimeInfo>?,
        attributes: Set<Asn1Element>? = null,
    ) : this(Parameters(
            publicKey = publicKey,
            privateKey = privateKey,
            prime1 = prime1,
            prime2 = prime2,
            prime1exponent = prime1exponent,
            prime2exponent = prime2exponent,
            crtCoefficient = crtCoefficient,
            otherPrimeInfos = otherPrimeInfos,
        ),
        attributes,
    )

    override val publicKey: RsaPublicKey get() = parameters.publicKey
    val privateKey: BigInteger get() = parameters.privateKey
    val prime1: BigInteger get() = parameters.prime1
    val prime2: BigInteger get() = parameters.prime2
    val prime1exponent: BigInteger get() = parameters.prime1exponent
    val prime2exponent: BigInteger get() = parameters.prime2exponent
    val crtCoefficient: BigInteger get() = parameters.crtCoefficient
    val otherPrimeInfos: List<PrimeInfo>? get() = parameters.otherPrimeInfos

    override fun equals(other: Any?): Boolean {
        if (other !is RsaPrivateKey) return false
        return publicKey.equalsCryptographically(other.publicKey)
    }

    override fun hashCode() = publicKey.hashCode()

    override fun toString() = "RSA private key for public key $publicKey"

    data class PrimeInfo(
        val prime: BigInteger,
        val exponent: BigInteger,
        val coefficient: BigInteger,
    ) : WithSourceRepresentation {
        @SignumInternals
        override val sourceRepresentation = SourceRepresentationStorage()
        companion object
    }

    companion object {
        val oid: ObjectIdentifier = KnownOIDs.rsaEncryption
    }

}

sealed class EcdsaPrivateKey private constructor(
    val privateKey: BigInteger,
    override val attributes: Set<Asn1Element>?,
) : CryptoPrivateKey {

    @SignumInternals
    override val sourceRepresentation = SourceRepresentationStorage()

    abstract val privateKeyBytes: ByteArray

    override fun equals(other: Any?): Boolean {
        if (other !is EcdsaPrivateKey) return false
        return privateKey == other.privateKey
    }

    override fun hashCode() = privateKey.hashCode()

    class WithPublicKey(
        privateKey: BigInteger,
        override val publicKey: EcdsaPublicKey,
        attributes: Set<Asn1Element>? = null,
    ) : EcdsaPrivateKey(privateKey, attributes),
        CryptoPrivateKey.WithPublicKey,
        KeyAgreementPrivateValue.ECDH {

        init {
            require(publicKey.publicPoint == privateKey.times(publicKey.curve.generator)) {
                "Public key must match the private key!"
            }
        }

        constructor(
            privateKey: BigInteger,
            curve: ECCurve,
            attributes: Set<Asn1Element>? = null,
        ) : this(
            privateKey,
            curve.generator.times(privateKey).asPublicKey(preferCompressed = true),
            attributes,
        )

        val curve: ECCurve get() = publicKey.curve

        override val privateKeyBytes: ByteArray
            get() = privateKey.toByteArray().ensureSize(curve.scalarLength.bytes)

        override val publicValue get() = publicKey

        override fun toString() = "EC private key for public key $publicKey"
    }

    class WithoutPublicKey(
        privateKey: BigInteger,
        val publicKeyBytes: Asn1BitString?,
        private val curveOrderLengthInBytes: Int,
        attributes: Set<Asn1Element>? = null,
    ) : EcdsaPrivateKey(privateKey, attributes) {

        fun withCurve(
            curve: ECCurve,
        ): WithPublicKey {
            require(curve.scalarLength.bytes.toInt() == curveOrderLengthInBytes) {
                "Encoded private key was padded to $curveOrderLengthInBytes bytes, but curve $curve needs padding to ${curve.scalarLength.bytes.toInt()} bytes"
            }
            return if (publicKeyBytes != null) {
                WithPublicKey(
                    privateKey,
                    EcdsaPublicKey.fromAnsiX963Bytes(curve, publicKeyBytes!!.bitCarryingBytes),
                    attributes,
                )
            } else {
                WithPublicKey(privateKey, curve, attributes)
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithoutPublicKey) return false
            if (!super.equals(other)) return false
            return curveOrderLengthInBytes == other.curveOrderLengthInBytes
        }

        override fun hashCode(): Int = 31 * super.hashCode() + curveOrderLengthInBytes

        override val privateKeyBytes: ByteArray
            get() = privateKey.toByteArray().ensureSize(curveOrderLengthInBytes)

    }

    companion object {
        val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

        internal fun iosDecodeInternal(keyBytes: ByteArray): EcdsaPrivateKey.WithPublicKey {
            val crv = ECCurve.fromIosEncodedPrivateKeyLength(keyBytes.size)
                ?: throw IllegalArgumentException("Unknown curve in iOS raw key")
            return WithPublicKey(
                BigInteger.fromByteArray(
                    keyBytes.sliceArray(crv.iosEncodedPublicKeyLength..<keyBytes.size),
                    Sign.POSITIVE,
                ),
                publicKey = EcdsaPublicKey.fromIosEncoded(
                    keyBytes.sliceArray(0..<crv.iosEncodedPublicKeyLength)
                ),
            )
        }
    }

}

internal fun positive(value: BigInteger): Asn1Integer.Positive =
    value.toAsn1Integer() as Asn1Integer.Positive

object IndispensablePrivateKeyFormatsProvider : PrivateKeyFormatProvider {
    override fun encodeToAsn1(value: CryptoPrivateKey): Pkcs8PrivateKeyInfo? = when (value) {
        is RsaPrivateKey -> value.toAsn1()
        is EcdsaPrivateKey -> value.toAsn1()
        else -> null
    }

    override fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo) : CryptoPrivateKey? {
        require(privateKeyInfo.version == Pkcs8PrivateKeyInfo.Version.V1) { "PKCS#8 Private Key VERSION must be 1" }
        return when (privateKeyInfo.algorithmOid) {
            RsaPrivateKey.oid -> RsaPrivateKey.fromAsn1(privateKeyInfo)
            EcdsaPrivateKey.oid -> EcdsaPrivateKey.fromAsn1(privateKeyInfo)
            else -> null
        }
    }
}
