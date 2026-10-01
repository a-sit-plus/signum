package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.asn1Representation
import at.asitplus.signum.indispensable.pki.fromAsn1Representation
import at.asitplus.signum.indispensable.sign.*
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
    override fun serialize(encoder: Encoder, value: T) = delegate.serialize(encoder, toModel(value))
    override fun deserialize(decoder: Decoder): T = fromModel(delegate.deserialize(decoder))
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

/** Register with DefaultDer before its first use, or include in a configured Der's serializersModule. */
val signumX509Serializers: SerializersModule = SerializersModule {
    contextual(TbsCertificate::class, TbsCertificateX509Serializer)
    contextual(Certificate::class, CertificateX509Serializer)
    contextual(SignatureAlgorithm::class, SignatureAlgorithmX509Serializer)
    contextual(EcdsaAlgorithm::class, EcdsaAlgorithmX509Serializer)
    contextual(RsaAlgorithm::class, RsaAlgorithmX509Serializer)
    contextual(CryptoPublicKey::class, CryptoPublicKeyX509Serializer)
    contextual(EcdsaPublicKey::class, EcdsaPublicKeyX509Serializer)
    contextual(RsaPublicKey::class, RsaPublicKeyX509Serializer)
}
