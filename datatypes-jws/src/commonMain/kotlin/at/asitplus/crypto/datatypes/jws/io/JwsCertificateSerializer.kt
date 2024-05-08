package at.asitplus.crypto.datatypes.jws.io

import at.asitplus.crypto.datatypes.pki.X509Certificate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

object JwsCertificateSerializer : KSerializer<X509Certificate> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor(serialName = "X509Certificate (JWS)", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): X509Certificate {
        @OptIn(ExperimentalEncodingApi::class)
        return X509Certificate.decodeFromDer(Base64.decode(decoder.decodeString()))
    }


    override fun serialize(encoder: Encoder, value: X509Certificate) {
        @OptIn(ExperimentalEncodingApi::class)
        encoder.encodeString(Base64.encode(value.encodeToDer()))
    }
}
