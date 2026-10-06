package at.asitplus.signum.indispensable.sign

import at.asitplus.signum.Signum
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo.Companion.invoke

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Pkcs1RsaOtherPrimeInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.ecPublicKey
import at.asitplus.awesn1.rsaEncryption
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.awesn1.toBigInteger
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.agree.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.PrivateKeyFormatProvider
import at.asitplus.signum.indispensable.equalsCryptographically
import at.asitplus.signum.indispensable.fromIosEncodedPrivateKeyLength
import at.asitplus.signum.indispensable.iosEncodedPublicKeyLength
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.internals.ensureSize
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

class RsaPrivateKey internal constructor(
    publicKeyProvider: () -> RsaPublicKey,
    privateKeyProvider: () -> BigInteger,
    prime1Provider: () -> BigInteger,
    prime2Provider: () -> BigInteger,
    prime1exponentProvider: () -> BigInteger,
    prime2exponentProvider: () -> BigInteger,
    crtCoefficientProvider: () -> BigInteger,
    otherPrimeInfosProvider: () -> List<PrimeInfo>?,
    override val representations: Map<Encodable.Representation, Any>,
    override val attributes: Set<Asn1Element>?,
) : CryptoPrivateKey, CryptoPrivateKey.WithPublicKey {

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
    ) : this(
        { publicKey },
        { privateKey },
        { prime1 },
        { prime2 },
        { prime1exponent },
        { prime2exponent },
        { crtCoefficient },
        { otherPrimeInfos },
        emptyMap(),
        attributes,
    )

    private val decodedPublicKey by lazy(publicKeyProvider)
    private val decodedPrivateKey by lazy(privateKeyProvider)
    private val decodedPrime1 by lazy(prime1Provider)
    private val decodedPrime2 by lazy(prime2Provider)
    private val decodedPrime1exponent by lazy(prime1exponentProvider)
    private val decodedPrime2exponent by lazy(prime2exponentProvider)
    private val decodedCrtCoefficient by lazy(crtCoefficientProvider)
    private val decodedOtherPrimeInfos by lazy(otherPrimeInfosProvider)

    // CRT checks cover the entire key and run once, on the first semantic access.
    private val validated by lazy {
        val publicKey = decodedPublicKey
        val privateKey = decodedPrivateKey
        val prime1 = decodedPrime1
        val prime2 = decodedPrime2
        val prime1exponent = decodedPrime1exponent
        val prime2exponent = decodedPrime2exponent
        val crtCoefficient = decodedCrtCoefficient
        val otherPrimeInfos = decodedOtherPrimeInfos
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

    override val publicKey: RsaPublicKey get() = validated.let { decodedPublicKey }
    val privateKey: BigInteger get() = validated.let { decodedPrivateKey }
    val prime1: BigInteger get() = validated.let { decodedPrime1 }
    val prime2: BigInteger get() = validated.let { decodedPrime2 }
    val prime1exponent: BigInteger get() = validated.let { decodedPrime1exponent }
    val prime2exponent: BigInteger get() = validated.let { decodedPrime2exponent }
    val crtCoefficient: BigInteger get() = validated.let { decodedCrtCoefficient }
    val otherPrimeInfos: List<PrimeInfo>? get() = validated.let { decodedOtherPrimeInfos }

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
    ) : Encodable {
        companion object : Decodable<PrimeInfo> {
            fun fromAsn1Representation(
                element: Pkcs1RsaOtherPrimeInfo): PrimeInfo =
                PrimeInfo(
                    element.prime.toBigInteger(),
                    element.exponent.toBigInteger(),
                    element.coefficient.toBigInteger())
        }
    }

    companion object : Decodable<RsaPrivateKey> {
        val oid: ObjectIdentifier = KnownOIDs.rsaEncryption
    }

}

sealed class EcdsaPrivateKey private constructor(
    privateKeyProvider: () -> BigInteger,
    override val representations: Map<Encodable.Representation, Any>,
    override val attributes: Set<Asn1Element>?,
) : CryptoPrivateKey {

    val privateKey by lazy(privateKeyProvider)
    abstract val privateKeyBytes: ByteArray

    override fun equals(other: Any?): Boolean {
        if (other !is EcdsaPrivateKey) return false
        return privateKey == other.privateKey
    }

    override fun hashCode() = privateKey.hashCode()

    class WithPublicKey internal constructor(
        privateKeyProvider: () -> BigInteger,
        publicKeyProvider: () -> EcdsaPublicKey,
        encodeCurveProvider: () -> Boolean,
        encodePublicKeyProvider: () -> Boolean,
        representations: Map<Encodable.Representation, Any>,
        attributes: Set<Asn1Element>?,
    ) : EcdsaPrivateKey(privateKeyProvider, representations, attributes),
        CryptoPrivateKey.WithPublicKey,
        KeyAgreementPrivateValue.ECDH {

        constructor(
            privateKey: BigInteger,
            publicKey: EcdsaPublicKey,
            encodeCurve: Boolean,
            encodePublicKey: Boolean,
            attributes: Set<Asn1Element>? = null,
        ) : this(
            { privateKey }, { publicKey }, { encodeCurve }, { encodePublicKey },
            emptyMap(), attributes,
        ) {
            require(publicKey.publicPoint == privateKey.times(publicKey.curve.generator)) {
                "Public key must match the private key!"
            }
        }

        constructor(
            privateKey: BigInteger,
            curve: ECCurve,
            encodeCurve: Boolean,
            encodePublicKey: Boolean,
            attributes: Set<Asn1Element>? = null,
        ) : this(
            privateKey,
            curve.generator.times(privateKey).asPublicKey(preferCompressed = true),
            encodeCurve,
            encodePublicKey,
            attributes,
        )

        override val publicKey by lazy(publicKeyProvider)

        val curve: ECCurve get() = publicKey.curve
        val encodeCurve by lazy(encodeCurveProvider)
        val encodePublicKey by lazy(encodePublicKeyProvider)

        override val privateKeyBytes: ByteArray
            get() = privateKey.toByteArray().ensureSize(curve.scalarLength.bytes)

        override val publicValue get() = publicKey

        override fun toString() = "EC private key for public key $publicKey"
    }

    class WithoutPublicKey internal constructor(
        privateKeyProvider: () -> BigInteger,
        publicKeyBytesProvider: () -> Asn1BitString?,
        curveOrderLengthInBytesProvider: () -> Int,
        representations: Map<Encodable.Representation, Any>,
        attributes: Set<Asn1Element>?,
    ) : EcdsaPrivateKey(privateKeyProvider, representations, attributes) {

        constructor(
            privateKey: BigInteger,
            publicKeyBytes: Asn1BitString?,
            attributes: Set<Asn1Element>? = null,
            curveOrderLengthInBytes: Int,
        ) : this(
            { privateKey }, { publicKeyBytes }, { curveOrderLengthInBytes },
            emptyMap(), attributes,
        )

        val publicKeyBytes by lazy(publicKeyBytesProvider)

        private val curveOrderLengthInBytes by lazy(curveOrderLengthInBytesProvider)

        fun withCurve(
            curve: ECCurve,
            encodeCurve: Boolean = true,
            encodePublicKey: Boolean = (this.publicKeyBytes != null),
        ): WithPublicKey {
            require(curve.scalarLength.bytes.toInt() == curveOrderLengthInBytes) {
                "Encoded private key was padded to $curveOrderLengthInBytes bytes, but curve $curve needs padding to ${curve.scalarLength.bytes.toInt()} bytes"
            }
            return if (publicKeyBytes != null) {
                WithPublicKey(
                    privateKey,
                    EcdsaPublicKey.fromAnsiX963Bytes(curve, publicKeyBytes!!.bitCarryingBytes),
                    encodeCurve,
                    encodePublicKey,
                    attributes,
                )
            } else {
                WithPublicKey(privateKey, curve, encodeCurve, encodePublicKey, attributes)
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

    companion object : Decodable<EcdsaPrivateKey> {
        val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

        internal fun iosDecodeInternal(keyBytes: ByteArray): EcdsaPrivateKey.WithPublicKey {
            val crv = ECCurve.fromIosEncodedPrivateKeyLength(keyBytes.size)
                ?: throw IllegalArgumentException("Unknown curve in iOS raw key")
            return WithPublicKey(
                BigInteger.fromByteArray(
                    keyBytes.sliceArray(crv.iosEncodedPublicKeyLength..<keyBytes.size),
                    Sign.POSITIVE,
                ),
                encodeCurve = false,
                encodePublicKey = true,
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
        is RsaPrivateKey -> Pkcs8PrivateKeyInfo.Companion(value.asPKCS1, value.attributes, Signum.Der)
        is EcdsaPrivateKey -> Pkcs8PrivateKeyInfo.Companion(value.asSEC1, value.curveOidForPkcs8(), value.attributes, Signum.Der)
        else -> null
    }

    override fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo) : CryptoPrivateKey? {
        require(privateKeyInfo.version == Pkcs8PrivateKeyInfo.Version.V1) { "PKCS#8 Private Key VERSION must be 1" }
        return when (privateKeyInfo.algorithmOid) {
            RsaPrivateKey.oid -> RsaPrivateKey.fromAsn1Representation(privateKeyInfo)
            EcdsaPrivateKey.oid -> EcdsaPrivateKey.fromAsn1Representation(privateKeyInfo)
            else -> null
        }
    }
}
