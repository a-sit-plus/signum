package at.asitplus.signum.indispensable.josef.io

import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.pki.X509Certificate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object JwsCertificateSerializer : KSerializer<X509Certificate> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(serialName = "X509Certificate (JWS)", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): X509Certificate {
        return X509Certificate.decodeFromDer(decoder.decodeString().decodeToByteArray(Base64Strict))
    }


    override fun serialize(encoder: Encoder, value: X509Certificate) {
        encoder.encodeString(value.encodeToDer().encodeToString(Base64Strict))
    }
}
