package at.asitplus.signum.indispensable.sign

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.EcdsaSigValue.Companion.toEcdsaSigValue
import at.asitplus.awesn1.crypto.Pkcs1RsaPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo.Companion.invoke
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.asAsn1BitString
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Decoders
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Encoders
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey.Companion.oid
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Parameters.PssPadded
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1
import at.asitplus.signum.indispensable.sign.RsaPrivateKey.Parameters
import at.asitplus.signum.indispensable.sign.RsaPrivateKey.PrimeInfo
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign

@Suppress("UNCHECKED_CAST")
val <reified T : RsaParams> RsaAlgorithm.Parameters<T>.asn1
    inline get() = asn1Encoders<T, RsaAlgorithm.Parameters<T>> { when (this) {
        is RsaAlgorithm.Parameters.Pkcs1Padded -> RsaPkcs1PaddingParams
        is PssPadded -> RsaSsaPssParams(
            hashAlgorithm = digest.asn1.toRepresentation(),
            maskGenAlgorithm = mgfAlgorithm.asn1.toRepresentation(),
            saltLength = saltLength.also { require(it <= Int.MAX_VALUE.toUInt()) }.toInt(),
            trailerField = trailerField,
        )
    } as T }

@Suppress("UNCHECKED_CAST")
val PssPadded.MaskGenerationFunction.asn1
    get() = asn1Encoders<X509AlgorithmIdentifier, _> {
        X509AlgorithmIdentifier(
            oid,
            (this as PssPadded.MaskGenerationFunction.Pkcs1Mgf1).digest.asn1.toRepresentation().element
        )
    }

@Suppress("UNCHECKED_CAST")
val PrimeInfo.asn1
    get() = asn1Encoders<Pkcs1RsaOtherPrimeInfo, _> {
        Pkcs1RsaOtherPrimeInfo(
            prime.toAsn1Integer() as Asn1Integer.Positive,
            exponent.toAsn1Integer() as Asn1Integer.Positive,
            coefficient.toAsn1Integer() as Asn1Integer.Positive,
        )
    }

class RsaPrivateKeyAsn1Converters(self: RsaPrivateKey) :
    Asn1EncodingHelpers.Asn1Encoders.WithPEM<Pkcs8PrivateKeyInfo> by
    (self.asn1Encoders {
        Pkcs8PrivateKeyInfo(it.asn1.pkcs1.toRepresentation(), null, Signum.Der)
    })
{

    val pkcs1 = self.asn1Encoders {
        Pkcs1RsaPrivateKeyInfo(
            version = if (it.otherPrimeInfos != null) Pkcs1RsaPrivateKeyInfo.Version.MULTI else Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME,
            modulus = it.publicKey.n,
            publicExponent = it.publicKey.e,
            privateExponent = positive(it.privateKey),
            prime1 = positive(it.prime1),
            prime2 = positive(it.prime2),
            exponent1 = positive(it.prime1exponent),
            exponent2 = positive(it.prime2exponent),
            coefficient = positive(it.crtCoefficient),
            otherPrimeInfos = it.otherPrimeInfos?.map<PrimeInfo, Pkcs1RsaOtherPrimeInfo> { it.asn1.toRepresentation() },
        )
    }

}

val RsaPrivateKey.asn1 get() = RsaPrivateKeyAsn1Converters(this)

class EcdsaPrivateKeyAsn1Converters(self: EcdsaPrivateKey) :
    Asn1EncodingHelpers.Asn1Encoders.WithPEM<Pkcs8PrivateKeyInfo> by
    (self.asn1Encoders {
        require (it is EcdsaPrivateKey.WithPublicKey) { "Curve information is missing, PKCS#8 encoding is not possible. Use withCurve()!" }
        Pkcs8PrivateKeyInfo(it.asn1.sec1.toRepresentation(), it.curve.oid, null, Signum.Der)
    })
{
    val sec1 = self.asn1Encoders {
        Sec1EcPrivateKeyInfo(
            version = Sec1EcPrivateKeyInfo.Version.V1,
            privateKey = it.privateKeyBytes,
            parameters = when (it) {
                is EcdsaPrivateKey.WithPublicKey -> it.curve.oid
                is EcdsaPrivateKey.WithoutPublicKey -> null
            },
            publicKey = when (it) {
                is EcdsaPrivateKey.WithPublicKey ->
                    Asn1.BitString(it.publicKey.iosEncoded).asAsn1BitString()

                is EcdsaPrivateKey.WithoutPublicKey -> it.publicKeyBytes?.let(Asn1BitString::invoke)
            },
        )
    }
}

val EcdsaPrivateKey.asn1 get() = EcdsaPrivateKeyAsn1Converters(this)

private fun decodeEcCurve(element: Asn1Element): ECCurve =
    ECCurve.withOid(ObjectIdentifier.decodeFromTlv(element as Asn1Primitive))

val PssPadded.Companion.fromAsn1 get() = asn1Decoders<RsaSsaPssParams,_> { src ->
    PssPadded(
        digest = Digest.fromAsn1(src.hashAlgorithm),
        mgfAlgorithm = PssPadded.MaskGenerationFunction.fromAsn1(src.maskGenAlgorithm),
        saltLength = src.saltLength.let { require(it >= 0); it.toUInt() },
        trailerField = src.trailerField,
    )
}

val PssPadded.MaskGenerationFunction.Companion.fromAsn1 get() = asn1Decoders<X509AlgorithmIdentifier,_> { element ->
    when (element.oid) {
        Pkcs1Mgf1.oid -> Pkcs1Mgf1(Digest.fromAsn1(element.parameters!!))
        else -> throw UnsupportedCryptoException("Unrecognized MGF OID ${element.oid}")
    }
}

object RsaAsn1Constructors :
    Asn1EncodingHelpers.Asn1Decoders<Pkcs8PrivateKeyInfo, RsaPrivateKey> by
    (asn1Decoders<Pkcs8PrivateKeyInfo,RsaPrivateKey> { src ->
        require(src.algorithmOid == RsaPrivateKey.oid) { "Expected RSA private key, got ${src.algorithmOid}" }
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
                    otherPrimeInfos = parsed.otherPrimeInfos?.map { PrimeInfo.fromAsn1(it) },
                )
            },
        )
    })
{

    val PKCS1 get() = asn1Decoders { src: Pkcs1RsaPrivateKeyInfo ->
        when (src.version) {
            Pkcs1RsaPrivateKeyInfo.Version.TWO_PRIME -> require(src.otherPrimeInfos == null) { "OtherPrimeInfos must be null for TWO_PRIME (version = 0) keys!" }
            Pkcs1RsaPrivateKeyInfo.Version.MULTI -> require(src.otherPrimeInfos != null) { "OtherPrimeInfos must be present for MULTI (version = 1) keys!" }
        }
        invoke(Pkcs8PrivateKeyInfo(src))
    }

    operator fun invoke(src: Pkcs1RsaPrivateKeyInfo) = PKCS1(src)
}

val RsaPrivateKey.Companion.fromAsn1 get() = RsaAsn1Constructors

val PrimeInfo.Companion.fromAsn1 get() =
    asn1Decoders<Pkcs1RsaOtherPrimeInfo,_> { element ->
        PrimeInfo(
            element.prime.toBigInteger(),
            element.exponent.toBigInteger(),
            element.coefficient.toBigInteger()
        )
    }

private fun ecPrivateKey(
    parsed: Sec1EcPrivateKeyInfo,
    curveFromPkcs8: Asn1Element?,
): EcdsaPrivateKey {
    require(parsed.version == Sec1EcPrivateKeyInfo.Version.V1) { "EC private key version must be 1" }
    val privateValue = BigInteger.fromByteArray(parsed.privateKey, Sign.POSITIVE)
    return if (parsed.parameters != null || curveFromPkcs8 != null) EcdsaPrivateKey.WithPublicKey(
        privateKey = privateValue,
        publicKey = run {
            val resolvedCurve = requireNotNull(
                parsed.parameters?.let(ECCurve::withOid) ?: curveFromPkcs8?.let(::decodeEcCurve)
            ) { "EC private key has no public key or curve" }
            parsed.publicKey?.let { EcdsaPublicKey.fromAnsiX963Bytes(resolvedCurve, it.bitCarryingBytes) }
                ?: resolvedCurve.generator.times(privateValue).asPublicKey(preferCompressed = true)
        },
    ) else EcdsaPrivateKey.WithoutPublicKey(
        privateKey = privateValue,
        publicKeyBytes = parsed.publicKey?.let { require(it.numPaddingBits == 0); it.bitCarryingBytes },
        curveOrderLengthInBytes = parsed.privateKey.size,
    )
}

object EcdsaAsn1Constructors :
    Asn1EncodingHelpers.Asn1Decoders<Pkcs8PrivateKeyInfo, EcdsaPrivateKey> by
    (asn1Decoders { src ->
        require(src.algorithmOid == oid) { "Expected EC private key, got ${src.algorithmOid}" }
        require(src.version == Pkcs8PrivateKeyInfo.Version.V1) { "Unsupported PKCS8 private key version: ${src.version}" }
        // Nested parsing uses the application-wide DER configuration (docs/docs/default-der.md).
        val parsed = Sec1EcPrivateKeyInfo.of(src, Signum.Der)
        return@asn1Decoders ecPrivateKey(
            parsed, src.algorithmParameters,
        )
    })
{

    val SEC1 get() = asn1Decoders { src: Sec1EcPrivateKeyInfo ->
        require(src.version == Sec1EcPrivateKeyInfo.Version.V1) { "Unsupported SEC1 private key version: ${src.version}" }
        ecPrivateKey(src, null)
    }

    operator fun invoke(src: Sec1EcPrivateKeyInfo) = SEC1(src)
}

val EcdsaPrivateKey.Companion.fromAsn1 get() = EcdsaAsn1Constructors

val EcdsaSignature.Companion.fromAsn1 get() =
    asn1Decoders<X509SignatureValue,_> { src ->
    val parsed = src.toEcdsaSigValue()
    EcdsaSignature.IndefiniteLength(
        r = parsed.r.toBigInteger(),
        s = parsed.s.toBigInteger(),
    )
}

val EcdsaSignature.IndefiniteLength.Companion.fromAsn1 get() = EcdsaSignature.fromAsn1

val RsaSignature.Companion.fromAsn1 get() =
    asn1Decoders<X509SignatureValue,_> { src ->
        RsaSignature(src.rawBytes)
    }
