package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DerDecoder
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.asn1Representation
import at.asitplus.signum.indispensable.pki.fromAsn1Representation
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.contextual

/** Register with DefaultDer before its first use, or include in a configured Der's serializersModule. */
val signumX509Serializers: SerializersModule = SerializersModule {
    contextual(TbsCertificate::class, TbsCertificateX509Serializer)
    contextual(Certificate::class, CertificateX509Serializer)
}

object TbsCertificateX509Serializer : KSerializer<TbsCertificate> {
    private val delegate = X509TbsCertificate.serializer()
    override val descriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: TbsCertificate) =
        delegate.serialize(encoder, value.asn1Representation)

    override fun deserialize(decoder: Decoder): TbsCertificate =
        TbsCertificate.fromAsn1Representation(delegate.deserialize(decoder), (decoder as? DerDecoder)?.der)
}

object CertificateX509Serializer : KSerializer<Certificate> {
    private val delegate = X509Certificate.serializer()
    override val descriptor = delegate.descriptor

    override fun serialize(encoder: Encoder, value: Certificate) =
        delegate.serialize(encoder, value.asn1Representation)

    override fun deserialize(decoder: Decoder): Certificate =
        Certificate.fromAsn1Representation(delegate.deserialize(decoder), (decoder as? DerDecoder)?.der)
}
