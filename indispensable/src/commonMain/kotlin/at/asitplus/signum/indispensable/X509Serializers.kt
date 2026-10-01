package at.asitplus.signum.indispensable

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
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual

private class X509Serializer<T, Model>(
    private val delegate: KSerializer<Model>,
    private val toModel: (T) -> Model,
    private val fromModel: (Model) -> T,
) : KSerializer<T> {
    override val descriptor = delegate.descriptor
    override fun serialize(encoder: Encoder, value: T) = encoder.encodeSerializableValue(delegate, toModel(value))
    override fun deserialize(decoder: Decoder): T = fromModel(decoder.decodeSerializableValue(delegate))
}

val TbsCertificateX509Serializer: KSerializer<TbsCertificate> = X509Serializer(
    X509TbsCertificate.serializer(), { it.asn1Representation }, { TbsCertificate.fromAsn1Representation(it) },
)
val CertificateX509Serializer: KSerializer<Certificate> = X509Serializer(
    X509Certificate.serializer(), { it.asn1Representation }, { Certificate.fromAsn1Representation(it) },
)
val SignatureAlgorithmX509Serializer: KSerializer<SignatureAlgorithm> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { SignatureAlgorithm.fromAsn1Representation(it) },
)
val EcdsaAlgorithmX509Serializer: KSerializer<EcdsaAlgorithm> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { EcdsaAlgorithm.fromAsn1Representation(it) },
)
val RsaAlgorithmX509Serializer: KSerializer<RsaAlgorithm> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { RsaAlgorithm.fromAsn1Representation(it) },
)
val CryptoPublicKeyX509Serializer: KSerializer<CryptoPublicKey> = X509Serializer(
    SubjectPublicKeyInfo.serializer(), { it.asn1Representation }, { CryptoPublicKey.fromAsn1Representation(it) },
)
val EcdsaPublicKeyX509Serializer: KSerializer<EcdsaPublicKey> = X509Serializer(
    SubjectPublicKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPublicKey(it) },
)
val RsaPublicKeyX509Serializer: KSerializer<RsaPublicKey> = X509Serializer(
    SubjectPublicKeyInfo.serializer(), { it.asn1Representation }, { RsaPublicKey(it) },
)

val CertificateExtensionX509Serializer: KSerializer<CertificateExtension> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509CertificateExtension.serializer(),
    { it.asn1Representation ?: throw SerializationException("Certificate extension ${it.oid} has no X.509 representation") },
    { CertificateExtension.fromAsn1Representation(it) },
)
val X509CertificateExtensionSerializer: KSerializer<X509CertificateExtension> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509CertificateExtension.serializer(),
    { it.asn1Representation }, { X509CertificateExtension(it) },
)

val DigestX509Serializer: KSerializer<Digest> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { Digest.fromAsn1Representation(it) },
)
val WellKnownDigestX509Serializer: KSerializer<WellKnownDigest> = X509Serializer(
    X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
    { Digest.fromAsn1Representation(it) as? WellKnownDigest
        ?: throw SerializationException("Digest ${it.oid} is not a WellKnownDigest") },
)

val CryptoPrivateKeyX509Serializer: KSerializer<CryptoPrivateKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { CryptoPrivateKey.fromAsn1Representation(it) },
)
val CryptoPrivateKeyWithPublicKeyX509Serializer: KSerializer<CryptoPrivateKey.WithPublicKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { CryptoPrivateKey.fromAsn1Representation(it) as? CryptoPrivateKey.WithPublicKey ?: throw SerializationException("Private key has no public key") },
)
val RsaPrivateKeyX509Serializer: KSerializer<RsaPrivateKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { RsaPrivateKey.fromAsn1Representation(it) },
)
val EcdsaPrivateKeyX509Serializer: KSerializer<EcdsaPrivateKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPrivateKey.fromAsn1Representation(it) },
)
val EcdsaPrivateKeyWithPublicKeyX509Serializer: KSerializer<EcdsaPrivateKey.WithPublicKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPrivateKey.fromAsn1Representation(it) as? EcdsaPrivateKey.WithPublicKey ?: throw SerializationException("EC key has no curve") },
)
val EcdsaPrivateKeyWithoutPublicKeyX509Serializer: KSerializer<EcdsaPrivateKey.WithoutPublicKey> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo.serializer(), { it.asn1Representation }, { EcdsaPrivateKey.fromAsn1Representation(it) as? EcdsaPrivateKey.WithoutPublicKey ?: throw SerializationException("EC key has a curve; decode as EcdsaPrivateKey") },
)
val RsaPrivateKeyPrimeInfoX509Serializer: KSerializer<RsaPrivateKey.PrimeInfo> = X509Serializer(
    at.asitplus.awesn1.crypto.Pkcs1RsaOtherPrimeInfo.serializer(), { it.asn1Representation }, { RsaPrivateKey.PrimeInfo.fromAsn1Representation(it) },
)
val SignatureValueX509Serializer: KSerializer<SignatureValue> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { SignatureValue.fromAsn1Representation(it) },
)
val CryptoSignatureX509Serializer: KSerializer<CryptoSignature> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { throw SerializationException("A signature BIT STRING has no algorithm; decode as SignatureValue, then supply its algorithm") },
)
val EcdsaSignatureX509Serializer: KSerializer<EcdsaSignature> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { EcdsaSignature.fromAsn1Representation(it) },
)
val EcdsaSignatureIndefiniteLengthX509Serializer: KSerializer<EcdsaSignature.IndefiniteLength> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { EcdsaSignature.fromAsn1Representation(it) },
)
val EcdsaSignatureDefiniteLengthX509Serializer: KSerializer<EcdsaSignature.DefiniteLength> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { throw SerializationException("ECDSA DER carries no scalar length; decode as EcdsaSignature, then use withCurve") },
)
val RsaSignatureX509Serializer: KSerializer<RsaSignature> = X509Serializer(
    at.asitplus.awesn1.crypto.X509SignatureValue.serializer(), { it.asn1Representation }, { RsaSignature.fromAsn1Representation(it) },
)
val MessageAuthenticationCodeX509Serializer: KSerializer<MessageAuthenticationCode> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { MessageAuthenticationCode.fromAsn1Representation(it) },
)
val HMACX509Serializer: KSerializer<HMAC> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { MessageAuthenticationCode.fromAsn1Representation(it) as? HMAC ?: throw SerializationException("Not an HMAC") },
)
val RsaAlgorithmParametersPssPaddedX509Serializer: KSerializer<RsaAlgorithm.Parameters.PssPadded> = X509Serializer(
    at.asitplus.awesn1.crypto.RsaSsaPssParams.serializer(), { it.asn1Representation }, { RsaAlgorithm.Parameters.PssPadded.fromAsn1Representation(it) },
)
val RsaAlgorithmParametersPkcs1PaddedX509Serializer: KSerializer<RsaAlgorithm.Parameters.Pkcs1Padded> = X509Serializer(
    at.asitplus.awesn1.crypto.RsaPkcs1PaddingParams.serializer(), { it.asn1Representation }, { throw SerializationException("PKCS#1 padding parameters carry no digest; decode the complete RsaAlgorithm") },
)
val RsaAlgorithmParametersPssPaddedMaskGenerationFunctionX509Serializer: KSerializer<RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.fromAsn1Representation(it) },
)
val RsaAlgorithmParametersPssPaddedMaskGenerationFunctionPkcs1Mgf1X509Serializer: KSerializer<RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1> = X509Serializer(
    at.asitplus.awesn1.crypto.X509AlgorithmIdentifier.serializer(), { it.asn1Representation }, { RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.fromAsn1Representation(it) as RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1 },
)
val NameX509Serializer: KSerializer<Name> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500Name.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { X500Name.fromAsn1Representation(it) },
)
val X500NameX509Serializer: KSerializer<X500Name> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500Name.serializer(), { it.asn1Representation }, { X500Name.fromAsn1Representation(it) },
)
val RelativeDistinguishedNameX509Serializer: KSerializer<RelativeDistinguishedName> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName.serializer(), { it.asn1Representation }, { RelativeDistinguishedName.fromAsn1Representation(it) },
)
val AttributeTypeAndValueX509Serializer: KSerializer<AttributeTypeAndValue> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { AttributeTypeAndValue.fromAsn1Representation(it) },
)
val BaseX509AttributeTypeAndValueX509Serializer: KSerializer<BaseX509AttributeTypeAndValue> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue.serializer(), { it.asn1Representation }, { BaseX509AttributeTypeAndValue(it) },
)
val GeneralNameX509Serializer: KSerializer<GeneralName> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509GeneralName.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { GeneralName.fromAsn1Representation(it) },
)
val BaseX509GeneralNameX509Serializer: KSerializer<BaseX509GeneralName> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509GeneralName.serializer(), { it.asn1Representation }, { BaseX509GeneralName(it) },
)
val AlternativeNamesX509Serializer: KSerializer<AlternativeNames> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.X509GeneralNames.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { AlternativeNames.fromAsn1Representation(it) },
)
val CsrAttributeX509Serializer: KSerializer<CsrAttribute> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute.serializer(), { requireNotNull(it.asn1Representation) { "Value has no X.509 representation" } }, { CsrAttribute.fromAsn1Representation(it) },
)
val X509CsrAttributeX509Serializer: KSerializer<X509CsrAttribute> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CsrAttribute.serializer(), { it.asn1Representation }, { X509CsrAttribute(it) },
)
val TbsCertificationRequestX509Serializer: KSerializer<TbsCertificationRequest> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo.serializer(), { it.asn1Representation }, { TbsCertificationRequest.fromAsn1Representation(it) },
)
val CertificationRequestX509Serializer: KSerializer<CertificationRequest> = X509Serializer(
    at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest.serializer(), { it.asn1Representation }, { CertificationRequest.fromAsn1Representation(it) },
)

/** Register with DefaultDer before its first use, or include in a configured Der's serializersModule. */
val signumX509Serializers: SerializersModule = SerializersModule {
    contextual(TbsCertificate::class, TbsCertificateX509Serializer)
    contextual(Certificate::class, CertificateX509Serializer)
    contextual(CertificateExtension::class, CertificateExtensionX509Serializer)
    contextual(X509CertificateExtension::class, X509CertificateExtensionSerializer)
    contextual(SignatureAlgorithm::class, SignatureAlgorithmX509Serializer)
    contextual(EcdsaAlgorithm::class, EcdsaAlgorithmX509Serializer)
    contextual(RsaAlgorithm::class, RsaAlgorithmX509Serializer)
    contextual(CryptoPublicKey::class, CryptoPublicKeyX509Serializer)
    contextual(EcdsaPublicKey::class, EcdsaPublicKeyX509Serializer)
    contextual(RsaPublicKey::class, RsaPublicKeyX509Serializer)
    contextual(Digest::class, DigestX509Serializer)
    contextual(WellKnownDigest::class, WellKnownDigestX509Serializer)
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

    contextual(CryptoPrivateKey::class, CryptoPrivateKeyX509Serializer)
    contextual(CryptoPrivateKey.WithPublicKey::class, CryptoPrivateKeyWithPublicKeyX509Serializer)
    contextual(RsaPrivateKey::class, RsaPrivateKeyX509Serializer)
    contextual(EcdsaPrivateKey::class, EcdsaPrivateKeyX509Serializer)
    contextual(EcdsaPrivateKey.WithPublicKey::class, EcdsaPrivateKeyWithPublicKeyX509Serializer)
    contextual(EcdsaPrivateKey.WithoutPublicKey::class, EcdsaPrivateKeyWithoutPublicKeyX509Serializer)
    contextual(RsaPrivateKey.PrimeInfo::class, RsaPrivateKeyPrimeInfoX509Serializer)
    contextual(SignatureValue::class, SignatureValueX509Serializer)
    contextual(CryptoSignature::class, CryptoSignatureX509Serializer)
    contextual(EcdsaSignature::class, EcdsaSignatureX509Serializer)
    contextual(EcdsaSignature.IndefiniteLength::class, EcdsaSignatureIndefiniteLengthX509Serializer)
    contextual(EcdsaSignature.DefiniteLength::class, EcdsaSignatureDefiniteLengthX509Serializer)
    contextual(RsaSignature::class, RsaSignatureX509Serializer)
    contextual(MessageAuthenticationCode::class, MessageAuthenticationCodeX509Serializer)
    contextual(HMAC::class, HMACX509Serializer)
    contextual(MessageAuthenticationCode.Truncated::class, X509Serializer(
        X509AlgorithmIdentifier.serializer(), { it.asn1Representation },
        { throw SerializationException("A truncated MAC has no X.509 representation") },
    ))
    contextual(RsaAlgorithm.Parameters.PssPadded::class, RsaAlgorithmParametersPssPaddedX509Serializer)
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
    contextual(RsaAlgorithm.Parameters.Pkcs1Padded::class, RsaAlgorithmParametersPkcs1PaddedX509Serializer)
    contextual(RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction::class, RsaAlgorithmParametersPssPaddedMaskGenerationFunctionX509Serializer)
    contextual(RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1::class, RsaAlgorithmParametersPssPaddedMaskGenerationFunctionPkcs1Mgf1X509Serializer)
    contextual(Name::class, NameX509Serializer)
    contextual(X500Name::class, X500NameX509Serializer)
    contextual(RelativeDistinguishedName::class, RelativeDistinguishedNameX509Serializer)
    contextual(AttributeTypeAndValue::class, AttributeTypeAndValueX509Serializer)
    contextual(BaseX509AttributeTypeAndValue::class, BaseX509AttributeTypeAndValueX509Serializer)
    contextual(GeneralName::class, GeneralNameX509Serializer)
    contextual(BaseX509GeneralName::class, BaseX509GeneralNameX509Serializer)
    contextual(AlternativeNames::class, AlternativeNamesX509Serializer)
    contextual(CsrAttribute::class, CsrAttributeX509Serializer)
    contextual(X509CsrAttribute::class, X509CsrAttributeX509Serializer)
    contextual(TbsCertificationRequest::class, TbsCertificationRequestX509Serializer)
    contextual(CertificationRequest::class, CertificationRequestX509Serializer)
}
