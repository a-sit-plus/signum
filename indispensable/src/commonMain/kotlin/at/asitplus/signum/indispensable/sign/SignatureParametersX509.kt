package at.asitplus.signum.indispensable.sign

import at.asitplus.signum.Signum

import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.EcdsaSigValue.Companion.toEcdsaSigValue
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.X509
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.ecmath.times
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import at.asitplus.awesn1.toAsn1Integer
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.asn1Representation
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo.Companion.invoke
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Parameters.PssPadded

@Suppress("UNCHECKED_CAST")
val <T : RsaParams> RsaAlgorithm.Parameters<T>.asn1Representation: T
    get() = (representations[X509] ?: when (this) {
        is RsaAlgorithm.Parameters.Pkcs1Padded -> RsaPkcs1PaddingParams
        is PssPadded -> RsaSsaPssParams(
            hashAlgorithm = digest.asn1Representation,
            maskGenAlgorithm = mgfAlgorithm.asn1Representation,
            saltLength = saltLength.also { require(it <= Int.MAX_VALUE.toUInt()) }.toInt(),
            trailerField = trailerField,
        )
    }) as T

@Suppress("UNCHECKED_CAST")
val RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.asn1Representation: X509AlgorithmIdentifier
    get() = representations[X509] as? X509AlgorithmIdentifier
        ?: X509AlgorithmIdentifier(oid, (this as PssPadded.MaskGenerationFunction.Pkcs1Mgf1).digest.asn1Representation.element)

@Suppress("UNCHECKED_CAST")
val RsaPrivateKey.PrimeInfo.asn1Representation: Pkcs1RsaOtherPrimeInfo
    get() = representations[X509] as? Pkcs1RsaOtherPrimeInfo
        ?: Pkcs1RsaOtherPrimeInfo(
            prime.toAsn1Integer() as Asn1Integer.Positive,
            exponent.toAsn1Integer() as Asn1Integer.Positive,
            coefficient.toAsn1Integer() as Asn1Integer.Positive,
        )

/** Alternate original encodings have their own representation keys. */
internal object PKCS1 : Encodable.Representation
internal object SEC1 : Encodable.Representation

val RsaPrivateKey.asPKCS1: Pkcs1RsaPrivateKeyInfo
    get() = representations[PKCS1] as? Pkcs1RsaPrivateKeyInfo
        // Nested conversion uses the application-wide DER configuration (docs/docs/default-der.md).
        ?: (representations[X509] as? Pkcs8PrivateKeyInfo)?.let { Pkcs1RsaPrivateKeyInfo.of(it, Signum.Der) }
        ?: toPkcs1Representation()
val EcdsaPrivateKey.asSEC1: Sec1EcPrivateKeyInfo
    get() = representations[SEC1] as? Sec1EcPrivateKeyInfo
        // Nested conversion uses the application-wide DER configuration (docs/docs/default-der.md).
        ?: (representations[X509] as? Pkcs8PrivateKeyInfo)?.let { Sec1EcPrivateKeyInfo.of(it, Signum.Der) }
        ?: toSec1Representation()

internal fun RsaPrivateKey.toPkcs1Representation(): Pkcs1RsaPrivateKeyInfo =
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

internal fun EcdsaPrivateKey.toSec1Representation(): Sec1EcPrivateKeyInfo =
    Sec1EcPrivateKeyInfo(
        version = Sec1EcPrivateKeyInfo.Version.V1,
        privateKey = privateKeyBytes,
        parameters = when (this) {
            is EcdsaPrivateKey.WithPublicKey -> if (encodeCurve) curve.oid else null
            is EcdsaPrivateKey.WithoutPublicKey -> null
        },
        publicKey = when (this) {
            is EcdsaPrivateKey.WithPublicKey ->
                if (encodePublicKey) Asn1.BitString(publicKey.iosEncoded).asAsn1BitString() else null
            is EcdsaPrivateKey.WithoutPublicKey -> publicKeyBytes
        },
    )

internal fun decodeEcCurve(element: Asn1Element): ECCurve =
    ECCurve.withOid(ObjectIdentifier.decodeFromTlv(element as Asn1Primitive))

internal fun EcdsaPrivateKey.curveOidForPkcs8(): ObjectIdentifier = when (this) {
    is EcdsaPrivateKey.WithPublicKey -> curve.oid
    is EcdsaPrivateKey.WithoutPublicKey -> throw Asn1StructuralException("Cannot PKCS#8-encode an EC key without curve. Use withCurve()!")
}

fun PssPadded.Companion.fromAsn1Representation(src: RsaSsaPssParams): PssPadded =
    PssPadded(
        digestProvider = { Digest.fromAsn1Representation(src.hashAlgorithm) },
        mgfAlgorithmProvider = { PssPadded.MaskGenerationFunction.fromAsn1Representation(src.maskGenAlgorithm) },
        saltLengthProvider = { src.saltLength.let { require(it >= 0); it.toUInt() } },
        trailerFieldProvider = { src.trailerField },
        representations = mapOf(X509 to src),
    )

operator fun PssPadded.Companion.invoke(src: RsaSsaPssParams): PssPadded = fromAsn1Representation(src)

private fun rsaPrivateKey(
    source: () -> Pkcs1RsaPrivateKeyInfo,
    representations: Map<Encodable.Representation, Any>,
    attributes: Set<Asn1Element>?,
): RsaPrivateKey {
    val parsed by lazy(source)
    return RsaPrivateKey(
        publicKeyProvider = { RsaPublicKey(parsed.modulus, parsed.publicExponent) },
        privateKeyProvider = { parsed.privateExponent.toBigInteger() },
        prime1Provider = { parsed.prime1.toBigInteger() },
        prime2Provider = { parsed.prime2.toBigInteger() },
        prime1exponentProvider = { parsed.exponent1.toBigInteger() },
        prime2exponentProvider = { parsed.exponent2.toBigInteger() },
        crtCoefficientProvider = { parsed.coefficient.toBigInteger() },
        otherPrimeInfosProvider = { parsed.otherPrimeInfos?.map { RsaPrivateKey.PrimeInfo.fromAsn1Representation(it) } },
        representations = representations,
        attributes = attributes,
    )
}

fun RsaPrivateKey.Companion.fromAsn1Representation(src: Pkcs8PrivateKeyInfo): RsaPrivateKey = runRethrowing {
    require(src.algorithmOid == oid) { "Expected RSA private key, got ${src.algorithmOid}" }
    require(src.version == Pkcs8PrivateKeyInfo.Version.V1) { "Unsupported PKCS8 private key version: ${src.version}" }
    // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    rsaPrivateKey({ Pkcs1RsaPrivateKeyInfo.of(src, Signum.Der) }, mapOf(X509 to src), src.attributes)
}

fun RsaPrivateKey.Companion.fromAsn1Representation(
    src: Pkcs1RsaPrivateKeyInfo,
    attributes: Set<Asn1Element>? = null,
): RsaPrivateKey {
    when (src.version) {
        Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME -> require(src.otherPrimeInfos == null) { "OtherPrimeInfos must be null for TWO_PRIME (version = 0) keys!" }
        Pkcs1RsaPrivateKeyInfo.Version.MULTI -> require(src.otherPrimeInfos != null) { "OtherPrimeInfos must be present for MULTI (version = 1) keys!" }
    }
    return rsaPrivateKey({ src }, mapOf(PKCS1 to src), attributes)
}

operator fun RsaPrivateKey.Companion.invoke(src: Pkcs8PrivateKeyInfo): RsaPrivateKey = fromAsn1Representation(src)
operator fun RsaPrivateKey.Companion.invoke(src: Pkcs1RsaPrivateKeyInfo): RsaPrivateKey = fromAsn1Representation(src)

private fun ecPrivateKey(
    source: () -> Sec1EcPrivateKeyInfo,
    curveFromPkcs8: () -> ECCurve?,
    hasCurve: Boolean,
    representations: Map<Encodable.Representation, Any>,
    attributes: Set<Asn1Element>?,
): EcdsaPrivateKey {
    val parsed by lazy {
        source().also { require(it.version == Sec1EcPrivateKeyInfo.Version.V1) { "EC private key version must be 1" } }
    }
    val curve by lazy { parsed.parameters?.let(ECCurve::withOid) ?: curveFromPkcs8() }
    val privateValue by lazy { BigInteger.fromByteArray(parsed.privateKey, Sign.POSITIVE) }
    return if (hasCurve) EcdsaPrivateKey.WithPublicKey(
        privateKeyProvider = { privateValue },
        publicKeyProvider = {
            val resolvedCurve = requireNotNull(curve) { "EC private key has no public key or curve" }
            parsed.publicKey?.let { EcdsaPublicKey.fromAnsiX963Bytes(resolvedCurve, it.bitCarryingBytes) }
                ?: resolvedCurve.generator.times(privateValue).asPublicKey(preferCompressed = true)
        },
        encodeCurveProvider = { parsed.parameters != null },
        encodePublicKeyProvider = { parsed.publicKey != null },
        representations = representations,
        attributes = attributes,
    ) else EcdsaPrivateKey.WithoutPublicKey(
        privateKeyProvider = { privateValue },
        publicKeyBytesProvider = { parsed.publicKey },
        curveOrderLengthInBytesProvider = { parsed.privateKey.size },
        representations = representations,
        attributes = attributes,
    )
}

fun EcdsaPrivateKey.Companion.fromAsn1Representation(
    src: Sec1EcPrivateKeyInfo,
    attributes: Set<Asn1Element>? = null,
): EcdsaPrivateKey {
    require(src.version == Sec1EcPrivateKeyInfo.Version.V1) { "Unsupported SEC1 private key version: ${src.version}" }
    return ecPrivateKey({ src }, { null }, src.parameters != null, mapOf(SEC1 to src), attributes)
}

fun EcdsaPrivateKey.Companion.fromAsn1Representation(src: Pkcs8PrivateKeyInfo): EcdsaPrivateKey {
    require(src.algorithmOid == oid) { "Expected EC private key, got ${src.algorithmOid}" }
    require(src.version == Pkcs8PrivateKeyInfo.Version.V1) { "Unsupported PKCS8 private key version: ${src.version}" }
    // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    val parsed by lazy { Sec1EcPrivateKeyInfo.of(src, Signum.Der) }
    val hasCurve = src.algorithmParameters != null || parsed.parameters != null
    if (!hasCurve) require(parsed.version == Sec1EcPrivateKeyInfo.Version.V1)
    return ecPrivateKey(
        { parsed }, { src.algorithmParameters?.let(::decodeEcCurve) }, hasCurve,
        mapOf(X509 to src), src.attributes,
    )
}

operator fun EcdsaPrivateKey.Companion.invoke(src: Pkcs8PrivateKeyInfo): EcdsaPrivateKey = fromAsn1Representation(src)
operator fun EcdsaPrivateKey.Companion.invoke(src: Sec1EcPrivateKeyInfo): EcdsaPrivateKey = fromAsn1Representation(src)

fun EcdsaSignature.Companion.fromAsn1Representation(src: X509SignatureValue): EcdsaSignature.IndefiniteLength {
    val parsed by lazy { src.toEcdsaSigValue() }
    return EcdsaSignature.IndefiniteLength(
        rProvider = { parsed.r.toBigInteger() },
        sProvider = { parsed.s.toBigInteger() },
        representations = mapOf(X509 to src),
    )
}

fun EcdsaSignature.IndefiniteLength.Companion.fromAsn1Representation(src: X509SignatureValue): EcdsaSignature.IndefiniteLength =
    EcdsaSignature.fromAsn1Representation(src)

fun RsaSignature.Companion.fromAsn1Representation(src: X509SignatureValue): RsaSignature =
    RsaSignature({ src.rawBytes }, mapOf(X509 to src))

operator fun EcdsaSignature.Companion.invoke(src: X509SignatureValue): EcdsaSignature.IndefiniteLength = fromAsn1Representation(src)
operator fun RsaSignature.Companion.invoke(src: X509SignatureValue): RsaSignature = fromAsn1Representation(src)
