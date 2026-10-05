package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import kotlinx.serialization.SerializationException
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.asn1Representation
import at.asitplus.signum.indispensable.pki.fromAsn1Representation
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.mac.*
import at.asitplus.signum.indispensable.mac.asn1Representation
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.digest.asn1Representation
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.reflect.KClass
import kotlinx.serialization.modules.SerializersModuleBuilder
import kotlinx.serialization.modules.SerializersModule

/** Register a contextual Signum serializer that delegates encoding to an awesn1 model. */
fun <T : Encodable, Model : Any> SerializersModuleBuilder.contextualAsn1(
    type: KClass<T>,
    modelSerializer: KSerializer<Model>,
    toModel: (T) -> Model,
    fromModel: (Model) -> T,
) {
    contextual(type, X509Serializer(modelSerializer, toModel, fromModel))
}

private class X509Serializer<T, Model>(
    private val delegate: KSerializer<Model>,
    private val toModel: (T) -> Model,
    private val fromModel: (Model) -> T,
) : KSerializer<T> {
    override val descriptor = delegate.descriptor
    override fun serialize(encoder: Encoder, value: T) = encoder.encodeSerializableValue(delegate, toModel(value))
    override fun deserialize(decoder: Decoder): T = fromModel(decoder.decodeSerializableValue(delegate))
}

val TbsCertificateAsn1Serializer: KSerializer<TbsCertificate> = X509Serializer(
    X509TbsCertificate.serializer(), { it.asn1Representation }, { TbsCertificate.fromAsn1Representation(it) },
)
val CertificateAsn1Serializer: KSerializer<Certificate> = X509Serializer(
    X509Certificate.serializer(), { it.asn1Representation }, { Certificate.fromAsn1Representation(it) },
)
val SignatureAlgorithmAsn1Serializer: KSerializer<SignatureAlgorithm> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { SignatureAlgorithm.fromAsn1Representation(it) },
)
val EcdsaAlgorithmAsn1Serializer: KSerializer<EcdsaAlgorithm> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { EcdsaAlgorithm.fromAsn1Representation(it) },
)
val RsaAlgorithmAsn1Serializer: KSerializer<RsaAlgorithm> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { RsaAlgorithm.fromAsn1Representation(it) },
)
val CryptoPublicKeyAsn1Serializer: KSerializer<CryptoPublicKey> = X509Serializer(
    SubjectPublicKeyInfo.serializer(), { it.asn1Representation }, { CryptoPublicKey.fromAsn1Representation(it) },
)
val EcdsaPublicKeyAsn1Serializer: KSerializer<EcdsaPublicKey> = X509Serializer(
    SubjectPublicKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPublicKey(it) },
)
val RsaPublicKeyAsn1Serializer: KSerializer<RsaPublicKey> = X509Serializer(
    SubjectPublicKeyInfo.serializer(), { it.asn1Representation }, { RsaPublicKey(it) },
)

val CertificateExtensionAsn1Serializer: KSerializer<CertificateExtension> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509CertificateExtension.serializer(),
    { it.asn1Representation ?: throw SerializationException("Certificate extension ${it.oid} has no X.509 representation") },
    { CertificateExtension.fromAsn1Representation(it) },
)
val X509CertificateExtensionSerializer: KSerializer<X509CertificateExtension> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509CertificateExtension.serializer(),
    { it.asn1Representation }, { X509CertificateExtension(it) },
)

val DigestAsn1Serializer: KSerializer<Digest> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { Digest.fromAsn1Representation(it) },
)
val WellKnownDigestAsn1Serializer: KSerializer<WellKnownDigest> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
    { Digest.fromAsn1Representation(it) as? WellKnownDigest
        ?: throw SerializationException("Digest ${it.oid} is not a WellKnownDigest") },
)


val CryptoPrivateKeyAsn1Serializer: KSerializer<CryptoPrivateKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { CryptoPrivateKey.fromAsn1Representation(it) },
)
val CryptoPrivateKeyWithPublicKeyAsn1Serializer: KSerializer<CryptoPrivateKey.WithPublicKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { CryptoPrivateKey.fromAsn1Representation(it) as? CryptoPrivateKey.WithPublicKey ?: throw SerializationException("Private key has no public key") },
)
val RsaPrivateKeyAsn1Serializer: KSerializer<RsaPrivateKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { RsaPrivateKey.fromAsn1Representation(it) },
)
val EcdsaPrivateKeyAsn1Serializer: KSerializer<EcdsaPrivateKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPrivateKey.fromAsn1Representation(it) },
)
val EcdsaPrivateKeyWithPublicKeyAsn1Serializer: KSerializer<EcdsaPrivateKey.WithPublicKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPrivateKey.fromAsn1Representation(it) as? EcdsaPrivateKey.WithPublicKey ?: throw SerializationException("EC key has no curve") },
)
val EcdsaPrivateKeyWithoutPublicKeyAsn1Serializer: KSerializer<EcdsaPrivateKey.WithoutPublicKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPrivateKey.fromAsn1Representation(it) as? EcdsaPrivateKey.WithoutPublicKey ?: throw SerializationException("EC key has a curve; decode as EcdsaPrivateKey") },
)
val RsaPrivateKeyPrimeInfoAsn1Serializer: KSerializer<RsaPrivateKey.PrimeInfo> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs1RsaOtherPrimeInfo.serializer(), { it.asn1Representation }, { RsaPrivateKey.PrimeInfo.fromAsn1Representation(it) },
)
val SignatureValueAsn1Serializer: KSerializer<SignatureValue> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { SignatureValue.fromAsn1Representation(it) },
)
val CryptoSignatureAsn1Serializer: KSerializer<CryptoSignature> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { throw SerializationException("A signature BIT STRING has no algorithm; decode as SignatureValue, then supply its algorithm") },
)
val EcdsaSignatureAsn1Serializer: KSerializer<EcdsaSignature> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { EcdsaSignature.fromAsn1Representation(it) },
)
val EcdsaSignatureIndefiniteLengthAsn1Serializer: KSerializer<EcdsaSignature.IndefiniteLength> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { EcdsaSignature.fromAsn1Representation(it) },
)
val EcdsaSignatureDefiniteLengthAsn1Serializer: KSerializer<EcdsaSignature.DefiniteLength> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { throw SerializationException("ECDSA DER carries no scalar length; decode as EcdsaSignature, then use withCurve") },
)
val RsaSignatureAsn1Serializer: KSerializer<RsaSignature> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { RsaSignature.fromAsn1Representation(it) },
)
val MessageAuthenticationCodeAsn1Serializer: KSerializer<MessageAuthenticationCode> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { MessageAuthenticationCode.fromAsn1Representation(it) },
)
val HMACAsn1Serializer: KSerializer<HMAC> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { MessageAuthenticationCode.fromAsn1Representation(it) as? HMAC ?: throw SerializationException("Not an HMAC") },
)
val RsaAlgorithmParametersPssPaddedAsn1Serializer: KSerializer<RsaAlgorithm.Parameters.PssPadded> = X509Serializer(
    at.asitplus.awesn1.crypto.RsaSsaPssParams.serializer(), { it.asn1Representation }, { RsaAlgorithm.Parameters.PssPadded.fromAsn1Representation(it) },
)
val RsaAlgorithmParametersPkcs1PaddedAsn1Serializer: KSerializer<RsaAlgorithm.Parameters.Pkcs1Padded> = X509Serializer(
    at.asitplus.awesn1.crypto.RsaPkcs1PaddingParams.serializer(), { it.asn1Representation }, { throw SerializationException("PKCS#1 padding parameters carry no digest; decode the complete RsaAlgorithm") },
)
val RsaAlgorithmParametersPssPaddedMaskGenerationFunctionAsn1Serializer: KSerializer<RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.fromAsn1Representation(it) },
)
val RsaAlgorithmParametersPssPaddedMaskGenerationFunctionPkcs1Mgf1Asn1Serializer: KSerializer<RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.fromAsn1Representation(it) as RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1 },
)
val NameAsn1Serializer: KSerializer<Name> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500Name.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { X500Name.fromAsn1Representation(it) },
)
val X500NameSerializer: KSerializer<X500Name> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500Name.serializer(), { it.asn1Representation }, { X500Name.fromAsn1Representation(it) },
)
val RelativeDistinguishedNameAsn1Serializer: KSerializer<RelativeDistinguishedName> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName.serializer(), { it.asn1Representation }, { RelativeDistinguishedName.fromAsn1Representation(it) },
)
val AttributeTypeAndValueXAsn1Serializer: KSerializer<AttributeTypeAndValue> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { AttributeTypeAndValue.fromAsn1Representation(it) },
)
val BaseX509AttributeTypeAndValueSerializer: KSerializer<BaseX509AttributeTypeAndValue> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue.serializer(), { it.asn1Representation }, { BaseX509AttributeTypeAndValue(it) },
)
val GeneralNameAsn1Serializer: KSerializer<GeneralName> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509GeneralName.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { GeneralName.fromAsn1Representation(it) },
)
val BaseX509GeneralNameAsn1Serializer: KSerializer<BaseX509GeneralName> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509GeneralName.serializer(), { it.asn1Representation }, { BaseX509GeneralName(it) },
)
val AlternativeNamesAsn1Serializer: KSerializer<AlternativeNames> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509GeneralNames.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { AlternativeNames.fromAsn1Representation(it) },
)
val CsrAttributeAsn1Serializer: KSerializer<CsrAttribute> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { CsrAttribute.fromAsn1Representation(it) },
)
val X509CsrAttributeAsn1Serializer: KSerializer<X509CsrAttribute> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute.serializer(), { it.asn1Representation }, { X509CsrAttribute(it) },
)
val TbsCertificationRequestAsn1Serializer: KSerializer<TbsCertificationRequest> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo.serializer(), { it.asn1Representation }, { TbsCertificationRequest.fromAsn1Representation(it) },
)
val CertificationRequestAsn1Serializer: KSerializer<CertificationRequest> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest.serializer(), { it.asn1Representation }, { CertificationRequest.fromAsn1Representation(it) },
)

/** Core contextual X.509 serializers, included automatically by Signum.Der; see docs/docs/default-der.md. */
val signumAsn1Serializers: SerializersModule = SerializersModule {
    contextual(TbsCertificate::class, TbsCertificateAsn1Serializer)
    contextual(Certificate::class, CertificateAsn1Serializer)
    contextual(CertificateExtension::class, CertificateExtensionAsn1Serializer)
    contextual(X509CertificateExtension::class, X509CertificateExtensionSerializer)
    contextual(SignatureAlgorithm::class, SignatureAlgorithmAsn1Serializer)
    contextual(EcdsaAlgorithm::class, EcdsaAlgorithmAsn1Serializer)
    contextual(RsaAlgorithm::class, RsaAlgorithmAsn1Serializer)
    contextual(CryptoPublicKey::class, CryptoPublicKeyAsn1Serializer)
    contextual(EcdsaPublicKey::class, EcdsaPublicKeyAsn1Serializer)
    contextual(RsaPublicKey::class, RsaPublicKeyAsn1Serializer)
    contextual(Digest::class, DigestAsn1Serializer)
    contextual(WellKnownDigest::class, WellKnownDigestAsn1Serializer)
    contextual(WellKnownDigest.SHA1::class, X509Serializer(
        X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
        { require(Digest.fromAsn1Representation(it) == WellKnownDigest.SHA1); WellKnownDigest.SHA1 },
    ))
    contextual(WellKnownDigest.SHA256::class, X509Serializer(
        X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
        { require(Digest.fromAsn1Representation(it) == WellKnownDigest.SHA256); WellKnownDigest.SHA256 },
    ))
    contextual(WellKnownDigest.SHA384::class, X509Serializer(
        X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
        { require(Digest.fromAsn1Representation(it) == WellKnownDigest.SHA384); WellKnownDigest.SHA384 },
    ))
    contextual(WellKnownDigest.SHA512::class, X509Serializer(
        X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
        { require(Digest.fromAsn1Representation(it) == WellKnownDigest.SHA512); WellKnownDigest.SHA512 },
    ))

    contextual(CryptoPrivateKey::class, CryptoPrivateKeyAsn1Serializer)
    contextual(CryptoPrivateKey.WithPublicKey::class, CryptoPrivateKeyWithPublicKeyAsn1Serializer)
    contextual(RsaPrivateKey::class, RsaPrivateKeyAsn1Serializer)
    contextual(EcdsaPrivateKey::class, EcdsaPrivateKeyAsn1Serializer)
    contextual(EcdsaPrivateKey.WithPublicKey::class, EcdsaPrivateKeyWithPublicKeyAsn1Serializer)
    contextual(EcdsaPrivateKey.WithoutPublicKey::class, EcdsaPrivateKeyWithoutPublicKeyAsn1Serializer)
    contextual(RsaPrivateKey.PrimeInfo::class, RsaPrivateKeyPrimeInfoAsn1Serializer)
    contextual(SignatureValue::class, SignatureValueAsn1Serializer)
    contextual(CryptoSignature::class, CryptoSignatureAsn1Serializer)
    contextual(EcdsaSignature::class, EcdsaSignatureAsn1Serializer)
    contextual(EcdsaSignature.IndefiniteLength::class, EcdsaSignatureIndefiniteLengthAsn1Serializer)
    contextual(EcdsaSignature.DefiniteLength::class, EcdsaSignatureDefiniteLengthAsn1Serializer)
    contextual(RsaSignature::class, RsaSignatureAsn1Serializer)
    contextual(MessageAuthenticationCode::class, MessageAuthenticationCodeAsn1Serializer)
    contextual(HMAC::class, HMACAsn1Serializer)
    contextual(MessageAuthenticationCode.Truncated::class, X509Serializer(
        X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
        { throw SerializationException("A truncated MAC has no X.509 representation") },
    ))
    contextual(RsaAlgorithm.Parameters.PssPadded::class, RsaAlgorithmParametersPssPaddedAsn1Serializer)
    contextual(RsaAlgorithm.Parameters::class) { typeArguments ->
        @Suppress("UNCHECKED_CAST")
        X509Serializer<RsaAlgorithm.Parameters<at.asitplus.awesn1.crypto.RsaParams>, at.asitplus.awesn1.crypto.RsaParams>(
            typeArguments.single() as KSerializer<at.asitplus.awesn1.crypto.RsaParams>,
            { it.asn1Representation },
            { when (it) {
                is at.asitplus.awesn1.crypto.RsaSsaPssParams -> RsaAlgorithm.Parameters.PssPadded.fromAsn1Representation(it)
                else -> throw SerializationException("PKCS#1 padding parameters carry no digest; decode the complete RsaAlgorithm")
            } },
        )
    }
    contextual(RsaAlgorithm.Parameters.Pkcs1Padded::class, RsaAlgorithmParametersPkcs1PaddedAsn1Serializer)
    contextual(RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction::class, RsaAlgorithmParametersPssPaddedMaskGenerationFunctionAsn1Serializer)
    contextual(RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1::class, RsaAlgorithmParametersPssPaddedMaskGenerationFunctionPkcs1Mgf1Asn1Serializer)
    contextual(Name::class, NameAsn1Serializer)
    contextual(X500Name::class, X500NameSerializer)
    contextual(RelativeDistinguishedName::class, RelativeDistinguishedNameAsn1Serializer)
    contextual(AttributeTypeAndValue::class, AttributeTypeAndValueXAsn1Serializer)
    contextual(BaseX509AttributeTypeAndValue::class, BaseX509AttributeTypeAndValueSerializer)
    contextual(GeneralName::class, GeneralNameAsn1Serializer)
    contextual(BaseX509GeneralName::class, BaseX509GeneralNameAsn1Serializer)
    contextual(AlternativeNames::class, AlternativeNamesAsn1Serializer)
    contextual(CsrAttribute::class, CsrAttributeAsn1Serializer)
    contextual(X509CsrAttribute::class, X509CsrAttributeAsn1Serializer)
    contextual(TbsCertificationRequest::class, TbsCertificationRequestAsn1Serializer)
    contextual(CertificationRequest::class, CertificationRequestAsn1Serializer)
}
