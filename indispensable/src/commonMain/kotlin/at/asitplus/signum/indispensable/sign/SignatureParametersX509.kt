package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.EcdsaSigValue.Companion.toEcdsaSigValue
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Encoders
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Parameters.PssPadded
import at.asitplus.signum.indispensable.sign.RsaPrivateKey.Parameters
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

@Suppress("UNCHECKED_CAST")
val <reified T : RsaParams> RsaAlgorithm.Parameters<T>.toAsn1
    inline get() = asn1Encoders<T, RsaAlgorithm.Parameters<T>> { when (this) {
        is RsaAlgorithm.Parameters.Pkcs1Padded -> RsaPkcs1PaddingParams
        is PssPadded -> RsaSsaPssParams(
            hashAlgorithm = digest.toAsn1(),
            maskGenAlgorithm = mgfAlgorithm.toAsn1(),
            saltLength = saltLength.also { require(it <= Int.MAX_VALUE.toUInt()) }.toInt(),
            trailerField = trailerField,
        )
    } as T }

@Suppress("UNCHECKED_CAST")
val PssPadded.MaskGenerationFunction.toAsn1
    get() = asn1Encoders<X509AlgorithmIdentifier, _> {
        X509AlgorithmIdentifier(
            oid,
            (this as PssPadded.MaskGenerationFunction.Pkcs1Mgf1).digest.toAsn1().element
        )
    }

@Suppress("UNCHECKED_CAST")
val RsaPrivateKey.PrimeInfo.toAsn1
    get() = asn1Encoders<Pkcs1RsaOtherPrimeInfo, _> {
        Pkcs1RsaOtherPrimeInfo(
            prime.toAsn1Integer() as Asn1Integer.Positive,
            exponent.toAsn1Integer() as Asn1Integer.Positive,
            coefficient.toAsn1Integer() as Asn1Integer.Positive,
        )
    }

// TODO: consider whether we want this to be its own source format (instead of wrapped into pkcs8)
// if we do: make pkcs1/sec1 an encoder/decoder pair each, and then make the pkcs8 encoder/decoder use those
val RsaPrivateKey.asPKCS1 get() =
    asn1Encoders<Pkcs1RsaPrivateKeyInfo,_> {
        Pkcs1RsaPrivateKeyInfo.of(this.toAsn1(), Signum.Der)
    }
val EcdsaPrivateKey.asSEC1 get() =
    asn1Encoders<Sec1EcPrivateKeyInfo,_> {
        Sec1EcPrivateKeyInfo.of(this.toAsn1(), Signum.Der)
    }

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
        otherPrimeInfos = otherPrimeInfos?.map { it.toAsn1() },
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
        digest = Digest.fromAsn1(src.hashAlgorithm),
        mgfAlgorithm = PssPadded.MaskGenerationFunction.fromAsn1Representation(src.maskGenAlgorithm),
        saltLength = src.saltLength.let { require(it >= 0); it.toUInt() },
        trailerField = src.trailerField,
    )

operator fun PssPadded.Companion.invoke(src: RsaSsaPssParams): PssPadded = fromAsn1Representation(src)

fun RsaPrivateKey.Companion.fromAsn1Representation(src: Pkcs8PrivateKeyInfo): RsaPrivateKey = runRethrowing {
    require(src.algorithmOid == oid) { "Expected RSA private key, got ${src.algorithmOid}" }
    require(src.version == Pkcs8PrivateKeyInfo.Version.V1) { "Unsupported PKCS8 private key version: ${src.version}" }
    // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    RsaPrivateKey(
        Pkcs1RsaPrivateKeyInfo.of(src, Signum.Der).let { parsed ->
            Parameters(
                publicKey = RsaPublicKey(parsed.modulus, parsed.publicExponent),
                privateKey = parsed.privateExponent.toBigInteger(),
                prime1 = parsed.prime1.toBigInteger(),
                prime2 = parsed.prime2.toBigInteger(),
                prime1exponent = parsed.exponent1.toBigInteger(),
                prime2exponent = parsed.exponent2.toBigInteger(),
                crtCoefficient = parsed.coefficient.toBigInteger(),
                otherPrimeInfos = parsed.otherPrimeInfos?.map { RsaPrivateKey.PrimeInfo.fromAsn1Representation(it) },
            )
        },
    )
}

fun RsaPrivateKey.Companion.fromAsn1Representation(
    src: Pkcs1RsaPrivateKeyInfo,
    attributes: Set<Asn1Element>? = null,
): RsaPrivateKey {
    when (src.version) {
        Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME -> require(src.otherPrimeInfos == null) { "OtherPrimeInfos must be null for TWO_PRIME (version = 0) keys!" }
        Pkcs1RsaPrivateKeyInfo.Version.MULTI -> require(src.otherPrimeInfos != null) { "OtherPrimeInfos must be present for MULTI (version = 1) keys!" }
    }
    return RsaPrivateKey(Pkcs8PrivateKeyInfo.invoke(src, attributes))
}

operator fun RsaPrivateKey.Companion.invoke(src: Pkcs8PrivateKeyInfo): RsaPrivateKey = fromAsn1Representation(src)
operator fun RsaPrivateKey.Companion.invoke(src: Pkcs1RsaPrivateKeyInfo): RsaPrivateKey = fromAsn1Representation(src)

// TODO: CLEAN THIS UP (there should be one canonical asn1 source for this)
private fun ecPrivateKey(
    parsed: Sec1EcPrivateKeyInfo,
    curveFromPkcs8: Asn1Element?,
    attributes: Set<Asn1Element>?,
): EcdsaPrivateKey {
    require(parsed.version == Sec1EcPrivateKeyInfo.Version.V1) { "EC private key version must be 1" }
    val privateValue = BigInteger.fromByteArray(parsed.privateKey, Sign.POSITIVE)
    return if (parsed.parameters != null || curveFromPkcs8 != null) EcdsaPrivateKey.WithPublicKey(
        privateKey = privateValue,
        publicKeyProvider = {
            val resolvedCurve = requireNotNull(
                parsed.parameters?.let(ECCurve::withOid) ?: curveFromPkcs8?.let(::decodeEcCurve)
            ) { "EC private key has no public key or curve" }
            parsed.publicKey?.let { EcdsaPublicKey.fromAnsiX963Bytes(resolvedCurve, it.bitCarryingBytes) }
                ?: resolvedCurve.generator.times(privateValue).asPublicKey(preferCompressed = true)
        },
        encodeCurve = parsed.parameters != null,
        encodePublicKey = parsed.publicKey != null,
        attributes = attributes,
    ) else EcdsaPrivateKey.WithoutPublicKey(
        privateKey = privateValue,
        publicKeyBytes = parsed.publicKey,
        curveOrderLengthInBytes = parsed.privateKey.size,
        attributes = attributes,
    )
}

fun EcdsaPrivateKey.Companion.fromAsn1Representation(
    src: Sec1EcPrivateKeyInfo,
    attributes: Set<Asn1Element>? = null,
): EcdsaPrivateKey {
    require(src.version == Sec1EcPrivateKeyInfo.Version.V1) { "Unsupported SEC1 private key version: ${src.version}" }
    return ecPrivateKey(src, null, attributes)
}

fun EcdsaPrivateKey.Companion.fromAsn1Representation(src: Pkcs8PrivateKeyInfo): EcdsaPrivateKey {
    require(src.algorithmOid == oid) { "Expected EC private key, got ${src.algorithmOid}" }
    require(src.version == Pkcs8PrivateKeyInfo.Version.V1) { "Unsupported PKCS8 private key version: ${src.version}" }
    // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
    val parsed = Sec1EcPrivateKeyInfo.of(src, Signum.Der)
    return ecPrivateKey(
        parsed, src.algorithmParameters,
        src.attributes,
    )
}

operator fun EcdsaPrivateKey.Companion.invoke(src: Pkcs8PrivateKeyInfo): EcdsaPrivateKey = fromAsn1Representation(src)
operator fun EcdsaPrivateKey.Companion.invoke(src: Sec1EcPrivateKeyInfo): EcdsaPrivateKey = fromAsn1Representation(src)

fun EcdsaSignature.Companion.fromAsn1Representation(src: X509SignatureValue): EcdsaSignature.IndefiniteLength {
    val parsed = src.toEcdsaSigValue()
    return EcdsaSignature.IndefiniteLength(
        r = parsed.r.toBigInteger(),
        s = parsed.s.toBigInteger(),
        // TODO the usual
    ).apply { @OptIn(SignumInternals::class) finangleSourceRepresentation(src) }
}

fun EcdsaSignature.IndefiniteLength.Companion.fromAsn1Representation(src: X509SignatureValue): EcdsaSignature.IndefiniteLength =
    EcdsaSignature.fromAsn1Representation(src)

fun RsaSignature.Companion.fromAsn1Representation(src: X509SignatureValue): RsaSignature =
    RsaSignature(src.rawBytes).apply { @OptIn(SignumInternals::class) finangleSourceRepresentation(src) }

operator fun EcdsaSignature.Companion.invoke(src: X509SignatureValue): EcdsaSignature.IndefiniteLength = fromAsn1Representation(src)
operator fun RsaSignature.Companion.invoke(src: X509SignatureValue): RsaSignature = fromAsn1Representation(src)
