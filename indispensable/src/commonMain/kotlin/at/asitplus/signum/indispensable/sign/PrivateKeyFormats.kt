package at.asitplus.signum.indispensable.sign
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo.Companion.invoke
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.signum.indispensable.iosEncoded

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Pkcs1RsaOtherPrimeInfo
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.ecPublicKey
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.rsaEncryption
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.serialization.decodeFromTlv
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
import at.asitplus.signum.internals.orLazy
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

class RsaPrivateKey private constructor(
    private val providedContent: ContentContainer?,
    private val providedPkcs1Source: RsaPkcs1Source?,
    private val providedPkcs8Representation: Pkcs8PrivateKeyInfo?,
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
        ContentContainer(
            publicKey = publicKey,
            privateKey = privateKey,
            prime1 = prime1,
            prime2 = prime2,
            prime1exponent = prime1exponent,
            prime2exponent = prime2exponent,
            crtCoefficient = crtCoefficient,
            otherPrimeInfos = otherPrimeInfos,
            attributes = attributes,
        ),
        null,
        null,
    )

    internal constructor(asn1Representation: Pkcs8PrivateKeyInfo) : this(null, null, asn1Representation)

    internal constructor(
        pkcs1Representation: Pkcs1RsaPrivateKeyInfo,
        attributes: Set<Asn1Element>? = null,
    ) : this(null, RsaPkcs1Source(pkcs1Representation, attributes), null)

    init {
        providedPkcs1Source?.let {
            when (it.pkcs1Representation.version) {
                Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME -> require(it.pkcs1Representation.otherPrimeInfos == null) { "OtherPrimeInfos must be null for TWO_PRIME (version = 0) keys!" }
                Pkcs1RsaPrivateKeyInfo.Version.MULTI -> require(it.pkcs1Representation.otherPrimeInfos != null) { "OtherPrimeInfos must be present for MULTI (version = 1) keys!" }
            }
        }

        providedPkcs8Representation?.let {
            require(it.version == Pkcs8PrivateKeyInfo.Version.V1) { "Unsupported PKCS8 private key version: ${it.version}" }
        }
    }

    private val content: ContentContainer by providedContent orLazy {
        val source = providedPkcs1Source ?: RsaPkcs1Source(
            Pkcs1RsaPrivateKeyInfo.of(requireNotNull(providedPkcs8Representation)),
            providedPkcs8Representation.attributes,
        )
        source.pkcs1Representation.toSignumContent(source.attributes)
    }

    override val attributes: Set<Asn1Element>? by lazy {
        providedContent?.attributes
            ?: providedPkcs8Representation?.attributes
            ?: providedPkcs1Source?.attributes
    }

    internal val pkcs1Representation: Pkcs1RsaPrivateKeyInfo by providedPkcs1Source?.pkcs1Representation orLazy {
        providedPkcs8Representation?.let { Pkcs1RsaPrivateKeyInfo.of(it) } ?: content.toPkcs1Representation()
    }

    override val representations: Map<Encodable.Representation, Any>

        get() = mapOf(X509 to x509Model)

    internal val x509Model: Pkcs8PrivateKeyInfo by providedPkcs8Representation orLazy {
        Pkcs8PrivateKeyInfo.Companion(pkcs1Representation, attributes)
    }


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
        override val representations: Map<Encodable.Representation, Any>
            get() = mapOf(X509 to x509Model)

        internal val x509Model: Pkcs1RsaOtherPrimeInfo
            get() = Pkcs1RsaOtherPrimeInfo(
                prime = positive(prime),
                exponent = positive(exponent),
                coefficient = positive(coefficient),
            )

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
        fun fromAsn1Representation(element: Pkcs1RsaPrivateKeyInfo): RsaPrivateKey = RsaPrivateKey(element)

        val oid: ObjectIdentifier = KnownOIDs.rsaEncryption

        fun fromAsn1Representation(
            element: Pkcs8PrivateKeyInfo): RsaPrivateKey = runRethrowing {
            require(element.algorithmOid == oid) { "Expected RSA private key, got ${element.algorithmOid}" }
            return RsaPrivateKey(element)
        }

    }

}

private fun Pkcs1RsaPrivateKeyInfo.toSignumContent(attributes: Set<Asn1Element>?): RsaPrivateKey.ContentContainer =
    RsaPrivateKey.ContentContainer(
        publicKey = RsaPublicKey(modulus, publicExponent),
        privateKey = privateExponent.toBigInteger(),
        prime1 = prime1.toBigInteger(),
        prime2 = prime2.toBigInteger(),
        prime1exponent = exponent1.toBigInteger(),
        prime2exponent = exponent2.toBigInteger(),
        crtCoefficient = coefficient.toBigInteger(),
        otherPrimeInfos = otherPrimeInfos?.map {
            RsaPrivateKey.PrimeInfo(
                it.prime.toBigInteger(),
                it.exponent.toBigInteger(),
                it.coefficient.toBigInteger()
            )
        },
        attributes = attributes,
    )

private fun RsaPrivateKey.ContentContainer.toPkcs1Representation(): Pkcs1RsaPrivateKeyInfo =
    Pkcs1RsaPrivateKeyInfo(
        version = if (otherPrimeInfos != null) Pkcs1RsaPrivateKeyInfo.Version.MULTI else Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME,
        modulus = publicKey.n,
        publicExponent = publicKey.e,
        privateExponent = positive(privateKey),
        prime1 = positive(prime1),
        prime2 = positive(prime2),
        exponent1 = positive(prime1exponent),
        exponent2 = positive(prime2exponent),
        coefficient = positive(crtCoefficient),
        otherPrimeInfos = otherPrimeInfos?.map { it.asn1Representation },
    )

private fun Sec1EcPrivateKeyInfo.toSignumContent(
    curveFromPkcs8: ECCurve?,
    attributes: Set<Asn1Element>?,
): EcdsaPrivateKey.ContentContainer {
    require(version == Sec1EcPrivateKeyInfo.Version.V1) { "EC public key version must be 1" }
    val curve = parameters?.let(ECCurve::withOid) ?: curveFromPkcs8
    val privateValue = BigInteger.fromByteArray(privateKey, Sign.POSITIVE)
    return if (curve != null) {
        EcdsaPrivateKey.ContentContainer(
            privateKey = privateValue,
            publicKey = publicKey?.let { EcdsaPublicKey.fromAnsiX963Bytes(curve, it.bitCarryingBytes) }
                ?: curve.generator.times(privateValue).asPublicKey(preferCompressed = true),
            publicKeyBytes = publicKey,
            encodeCurve = parameters != null,
            encodePublicKey = publicKey != null,
            curveOrderLengthInBytes = privateKey.size,
            attributes = attributes,
        )
    } else {
        EcdsaPrivateKey.ContentContainer(
            privateKey = privateValue,
            publicKey = null,
            publicKeyBytes = publicKey,
            encodeCurve = false,
            encodePublicKey = publicKey != null,
            curveOrderLengthInBytes = privateKey.size,
            attributes = attributes,
        )
    }
}

private fun EcdsaPrivateKey.ContentContainer.toSec1Representation(): Sec1EcPrivateKeyInfo =
    Sec1EcPrivateKeyInfo(
        version = Sec1EcPrivateKeyInfo.Version.V1,
        privateKey = privateKey.toByteArray().ensureSize(curveOrderLengthInBytes.toUInt()),
        parameters = publicKey?.curve?.oid?.takeIf { encodeCurve },
        publicKey = when {
            publicKey != null && encodePublicKey -> Asn1.BitString(publicKey.iosEncoded).asAsn1BitString()
            publicKey == null && encodePublicKey -> publicKeyBytes
            else -> null
        },
    )

private fun decodeEcCurve(element: Asn1Element): ECCurve =
    ECCurve.withOid(ObjectIdentifier.decodeFromTlv(element as Asn1Primitive))

sealed class EcdsaPrivateKey private constructor(
    private val providedContent: ContentContainer?,
    private val providedSec1Source: EcSec1Source?,
    private val providedPkcs8Representation: Pkcs8PrivateKeyInfo?,
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

    init {
        providedSec1Source?.let {
            require(it.sec1Representation.version == Sec1EcPrivateKeyInfo.Version.V1) { "Unsupported SEC1 private key version: ${it.sec1Representation.version}" }
        }

        providedPkcs8Representation?.let {
            require(it.version == Pkcs8PrivateKeyInfo.Version.V1) { "Unsupported PKCS8 private key version: ${it.version}" }
        }
    }

    protected val content: ContentContainer by providedContent orLazy {
        val source = providedSec1Source ?: requireNotNull(providedPkcs8Representation).let {
            EcSec1Source(Sec1EcPrivateKeyInfo.of(it), it.algorithmParameters?.let(::decodeEcCurve), it.attributes)
        }
        source.sec1Representation.toSignumContent(source.curveFromPkcs8, source.attributes)
    }

    override val attributes: Set<Asn1Element>? by lazy {
        providedContent?.attributes
            ?: providedPkcs8Representation?.attributes
            ?: providedSec1Source?.attributes
    }

    val privateKey: BigInteger get() = content.privateKey

    abstract val privateKeyBytes: ByteArray

    internal val sec1Representation: Sec1EcPrivateKeyInfo by providedSec1Source?.sec1Representation orLazy {
        providedPkcs8Representation?.let { Sec1EcPrivateKeyInfo.of(it) } ?: content.toSec1Representation()
    }

    override val representations: Map<Encodable.Representation, Any>

        get() = mapOf(X509 to x509Model)

    internal val x509Model: Pkcs8PrivateKeyInfo by providedPkcs8Representation orLazy {
        Pkcs8PrivateKeyInfo.Companion(sec1Representation, curveOidForPkcs8(), attributes)
    }


    protected abstract fun curveOidForPkcs8(): ObjectIdentifier?

    override fun equals(other: Any?): Boolean {
        if (other !is EcdsaPrivateKey) return false
        return privateKey == other.privateKey
    }

    override fun hashCode() = privateKey.hashCode()

    class WithPublicKey private constructor(
        providedContent: ContentContainer?,
        providedSec1Source: EcSec1Source?,
        providedPkcs8Representation: Pkcs8PrivateKeyInfo?,
    ) : EcdsaPrivateKey(providedContent, providedSec1Source, providedPkcs8Representation),
        CryptoPrivateKey.WithPublicKey,
        KeyAgreementPrivateValue.ECDH {

        constructor(
            privateKey: BigInteger,
            publicKey: EcdsaPublicKey,
            encodeCurve: Boolean,
            encodePublicKey: Boolean,
            attributes: Set<Asn1Element>? = null,
        ) : this(
            ContentContainer(
                privateKey = privateKey,
                publicKey = publicKey,
                publicKeyBytes = null,
                encodeCurve = encodeCurve,
                encodePublicKey = encodePublicKey,
                curveOrderLengthInBytes = publicKey.curve.scalarLength.bytes.toInt(),
                attributes = attributes,
            ),
            null,
            null,
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

        internal constructor(source: EcSec1Source) : this(null, source, null)
        internal constructor(asn1Representation: Pkcs8PrivateKeyInfo) : this(null, null, asn1Representation)

        override val publicKey: EcdsaPublicKey by content.publicKey orLazy {
            val curve = curve
            content.publicKeyBytes?.let {
                EcdsaPublicKey.fromAnsiX963Bytes(curve, it.bitCarryingBytes)
            } ?: curve.generator.times(privateKey).asPublicKey(preferCompressed = true)
        }

        val curve: ECCurve get() = publicKey.curve
        val encodeCurve: Boolean get() = content.encodeCurve
        val encodePublicKey: Boolean get() = content.encodePublicKey

        override val privateKeyBytes: ByteArray
            get() = privateKey.toByteArray().ensureSize(curve.scalarLength.bytes)

        override val publicValue get() = publicKey

        override fun curveOidForPkcs8(): ObjectIdentifier = curve.oid

        override fun toString() = "EC private key for public key $publicKey"
    }

    class WithoutPublicKey private constructor(
        providedContent: ContentContainer?,
        providedSec1Source: EcSec1Source?,
    ) : EcdsaPrivateKey(providedContent, providedSec1Source, null) {

        constructor(
            privateKey: BigInteger,
            publicKeyBytes: Asn1BitString?,
            attributes: Set<Asn1Element>? = null,
            curveOrderLengthInBytes: Int,
        ) : this(
            ContentContainer(
                privateKey = privateKey,
                publicKey = null,
                publicKeyBytes = publicKeyBytes,
                encodeCurve = false,
                encodePublicKey = publicKeyBytes != null,
                curveOrderLengthInBytes = curveOrderLengthInBytes,
                attributes = attributes,
            ),
            null,
        )

        internal constructor(source: EcSec1Source) : this(null, source)

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

        override fun curveOidForPkcs8(): Nothing =
            throw Asn1StructuralException("Cannot PKCS#8-encode an EC key without curve. Use withCurve()!")
    }

    companion object : Decodable<EcdsaPrivateKey> {
        fun fromAsn1Representation(
            representation: Sec1EcPrivateKeyInfo,
            attributes: Set<Asn1Element>? = null,
        ): EcdsaPrivateKey {
            val source = EcSec1Source(representation, representation.parameters?.let(ECCurve::withOid), attributes)
            return if (source.curveFromPkcs8 != null) WithPublicKey(source) else WithoutPublicKey(source)
        }


        val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

        fun fromAsn1Representation(
            element: Pkcs8PrivateKeyInfo): EcdsaPrivateKey {
            require(element.algorithmOid == oid) { "Expected EC private key, got ${element.algorithmOid}" }
            return fromPkcs8Representation(element)
        }

        private fun fromPkcs8Representation(representation: Pkcs8PrivateKeyInfo): EcdsaPrivateKey {
            val curve = representation.algorithmParameters?.let(::decodeEcCurve)
            return when {
                curve != null -> WithPublicKey(representation)
                Sec1EcPrivateKeyInfo.of(representation).parameters != null -> WithPublicKey(representation)
                else -> WithoutPublicKey(
                    EcSec1Source(
                        Sec1EcPrivateKeyInfo.of(representation),
                        null,
                        representation.attributes
                    )
                )
            }
        }

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

data class RsaPkcs1Source(
    val pkcs1Representation: Pkcs1RsaPrivateKeyInfo,
    val attributes: Set<Asn1Element>?,
)

data class EcSec1Source(
    val sec1Representation: Sec1EcPrivateKeyInfo,
    val curveFromPkcs8: ECCurve?,
    val attributes: Set<Asn1Element>?,
)

private fun positive(value: BigInteger): Asn1Integer.Positive =
    value.toAsn1Integer() as Asn1Integer.Positive

object IndispensablePrivateKeyFormatsProvider : PrivateKeyFormatProvider {
    override fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo) : CryptoPrivateKey? {
        require(privateKeyInfo.version == Pkcs8PrivateKeyInfo.Version.V1) { "PKCS#8 Private Key VERSION must be 1" }
        return when (privateKeyInfo.algorithmOid) {
            RsaPrivateKey.oid -> RsaPrivateKey.fromAsn1Representation(privateKeyInfo)
            EcdsaPrivateKey.oid -> EcdsaPrivateKey.fromAsn1Representation(privateKeyInfo)
            else -> null
        }
    }
}
