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
    contentProvider: () -> ContentContainer,
    override val representations: Map<Encodable.Representation, Any>,
    override val attributes: Set<Asn1Element>?,
) : CryptoPrivateKey, CryptoPrivateKey.WithPublicKey {

    data class ContentContainer(
        val publicKey: RsaPublicKey,
        val privateKey: BigInteger,
        val prime1: BigInteger,
        val prime2: BigInteger,
        val prime1exponent: BigInteger,
        val prime2exponent: BigInteger,
        val crtCoefficient: BigInteger,
        val otherPrimeInfos: List<RsaPrivateKey.PrimeInfo>?,
        val attributes: Set<Asn1Element>?,
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
    ) : this(
        { ContentContainer(
            publicKey = publicKey,
            privateKey = privateKey,
            prime1 = prime1,
            prime2 = prime2,
            prime1exponent = prime1exponent,
            prime2exponent = prime2exponent,
            crtCoefficient = crtCoefficient,
            otherPrimeInfos = otherPrimeInfos,
            attributes = attributes,
        ) },
        emptyMap(),
        attributes,
    )

    internal val content by lazy(contentProvider)

    override val publicKey: RsaPublicKey get() = content.publicKey
    val privateKey: BigInteger get() = content.privateKey
    val prime1: BigInteger get() = content.prime1
    val prime2: BigInteger get() = content.prime2
    val prime1exponent: BigInteger get() = content.prime1exponent
    val prime2exponent: BigInteger get() = content.prime2exponent
    val crtCoefficient: BigInteger get() = content.crtCoefficient
    val otherPrimeInfos: List<PrimeInfo>? get() = content.otherPrimeInfos

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
    contentProvider: () -> ContentContainer,
    override val representations: Map<Encodable.Representation, Any>,
    override val attributes: Set<Asn1Element>?,
) : CryptoPrivateKey {

    data class ContentContainer(
        val privateKey: BigInteger,
        val publicKey: EcdsaPublicKey?,
        val publicKeyBytes: Asn1BitString?,
        val encodeCurve: Boolean,
        val encodePublicKey: Boolean,
        val curveOrderLengthInBytes: Int,
        val attributes: Set<Asn1Element>?,
    )

    internal val content by lazy(contentProvider)

    val privateKey: BigInteger get() = content.privateKey
    abstract val privateKeyBytes: ByteArray

    override fun equals(other: Any?): Boolean {
        if (other !is EcdsaPrivateKey) return false
        return privateKey == other.privateKey
    }

    override fun hashCode() = privateKey.hashCode()

    class WithPublicKey internal constructor(
        contentProvider: () -> ContentContainer,
        representations: Map<Encodable.Representation, Any>,
        attributes: Set<Asn1Element>?,
    ) : EcdsaPrivateKey(contentProvider, representations, attributes),
        CryptoPrivateKey.WithPublicKey,
        KeyAgreementPrivateValue.ECDH {

        constructor(
            privateKey: BigInteger,
            publicKey: EcdsaPublicKey,
            encodeCurve: Boolean,
            encodePublicKey: Boolean,
            attributes: Set<Asn1Element>? = null,
        ) : this(
            { ContentContainer(
                privateKey = privateKey,
                publicKey = publicKey,
                publicKeyBytes = null,
                encodeCurve = encodeCurve,
                encodePublicKey = encodePublicKey,
                curveOrderLengthInBytes = publicKey.curve.scalarLength.bytes.toInt(),
                attributes = attributes,
            ) },
            emptyMap(),
            attributes,
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

        override val publicKey: EcdsaPublicKey by lazy {
            requireNotNull(content.publicKey) { "EC private key has no public key or curve" }
        }

        val curve: ECCurve get() = publicKey.curve
        val encodeCurve: Boolean get() = content.encodeCurve
        val encodePublicKey: Boolean get() = content.encodePublicKey

        override val privateKeyBytes: ByteArray
            get() = privateKey.toByteArray().ensureSize(curve.scalarLength.bytes)

        override val publicValue get() = publicKey

        override fun toString() = "EC private key for public key $publicKey"
    }

    class WithoutPublicKey internal constructor(
        contentProvider: () -> ContentContainer,
        representations: Map<Encodable.Representation, Any>,
        attributes: Set<Asn1Element>?,
    ) : EcdsaPrivateKey(contentProvider, representations, attributes) {

        constructor(
            privateKey: BigInteger,
            publicKeyBytes: Asn1BitString?,
            attributes: Set<Asn1Element>? = null,
            curveOrderLengthInBytes: Int,
        ) : this(
            { ContentContainer(
                privateKey = privateKey,
                publicKey = null,
                publicKeyBytes = publicKeyBytes,
                encodeCurve = false,
                encodePublicKey = publicKeyBytes != null,
                curveOrderLengthInBytes = curveOrderLengthInBytes,
                attributes = attributes,
            ) },
            emptyMap(),
            attributes,
        )

        val publicKeyBytes: Asn1BitString? get() = content.publicKeyBytes

        private val curveOrderLengthInBytes: Int get() = content.curveOrderLengthInBytes

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
