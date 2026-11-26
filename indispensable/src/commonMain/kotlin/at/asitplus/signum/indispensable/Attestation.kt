package at.asitplus.signum.indispensable

import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.CertificateChainBase64UrlSerializer
import at.asitplus.signum.indispensable.io.IosPublicKeySerializer
import at.asitplus.signum.indispensable.io.X509CertificateBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.signum.indispensable.sign.fromAsn1
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.JsonClassDiscriminator

@Serializable
@JsonClassDiscriminator("typ")
sealed interface Attestation {
    companion object {
        fun fromJSON(v: String) = Json.decodeFromString<Attestation>(v)
    }
}

@Serializable
@SerialName("self")
data class SelfAttestation (
    @Serializable(with=X509CertificateBase64UrlSerializer::class)
    @SerialName("x5c")
    val certificate: Certificate) : Attestation

@Serializable
@SerialName("android-key")
data class AndroidKeystoreAttestation (
    @Serializable(with=CertificateChainBase64UrlSerializer::class)
    @SerialName("x5c")
    val certificateChain: CertificateChain) : Attestation

val StrictJson = Json { ignoreUnknownKeys = true; isLenient = false }

@Serializable
@SerialName("ios-appattest")
data class IosHomebrewAttestation(
    @Serializable(with=ByteArrayBase64UrlSerializer::class)
    val attestation: ByteArray,
    @Serializable(with=ByteArrayBase64UrlSerializer::class)
    val clientDataJSON: ByteArray): Attestation {

    companion object { const val THE_PURPOSE = "ios app-attest: secure enclave protected key" }

    @Serializable(with = ClientData.Serializer::class)
    @ConsistentCopyVisibility
    data class ClientData private constructor(
        private val purpose: String,
        val publicKey: PublicKey,
        val challenge: ByteArray,
    ) {
        constructor(publicKey: PublicKey, challenge: ByteArray) :
            this(THE_PURPOSE, publicKey, challenge)

        internal fun assertValidity() { if (purpose != THE_PURPOSE) throw IllegalStateException("Invalid purpose") }

        /**
         * Computes the ByteArray that is used to compute the client data hash input for `DCAppAttest`.
         * This is effectively the ByteArray-Representation of this data's JSON encoding.
         */
        fun prepareDigestInput(): ByteArray = Json.encodeToString(this).encodeToByteArray()

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other == null || this::class != other::class) return false

            other as ClientData

            if (purpose != other.purpose) return false
            if (publicKey != other.publicKey) return false
            return challenge.contentEquals(other.challenge)
        }

        override fun hashCode(): Int {
            var result = purpose.hashCode()
            result = 31 * result + publicKey.hashCode()
            result = 31 * result + challenge.contentHashCode()
            return result
        }

        @OptIn(SignumInternals::class)
        object Serializer : KSerializer<ClientData> {
            override val descriptor: SerialDescriptor = LegacyClientDataWire.serializer().descriptor

            override fun serialize(encoder: Encoder, value: ClientData) {
                if (value.publicKey.isLegacyIosKey()) {
                    encoder.encodeSerializableValue(
                        LegacyClientDataWire.serializer(),
                        LegacyClientDataWire(value.purpose, value.publicKey, value.challenge)
                    )
                } else {
                    if (encoder !is JsonEncoder) throw SerializationException("ClientData v2 requires a JSON encoder")
                    encoder.encodeSerializableValue(
                        Version2ClientDataWire.serializer(),
                        Version2ClientDataWire(value.purpose, value.publicKey.asn1.toDer(), value.challenge, 2)
                    )
                }
            }

            override fun deserialize(decoder: Decoder): ClientData {
                if (decoder !is JsonDecoder) {
                    return decoder.decodeSerializableValue(LegacyClientDataWire.serializer()).toClientData()
                }
                val obj = decoder.decodeJsonElement() as? JsonObject
                    ?: throw SerializationException("ClientData must be a JSON object")
                val version = obj["version"]
                    ?: return decoder.json.decodeFromJsonElement(LegacyClientDataWire.serializer(), obj).toClientData()
                if (version !is JsonPrimitive || version.isString || version.content != "2") {
                    throw SerializationException("Unsupported ClientData version")
                }
                val wire = decoder.json.decodeFromJsonElement(Version2ClientDataWire.serializer(), obj)
                val publicKey = PublicKey.fromAsn1(wire.publicKey)
                if (publicKey is PublicKey.Unknown) {
                    throw SerializationException("No key format provider decoded the v2 public key")
                }
                return ClientData(wire.purpose, publicKey, wire.challenge)
            }

            private fun LegacyClientDataWire.toClientData() = ClientData(purpose, publicKey, challenge)
        }
    }

    val parsedClientData: ClientData by lazy {
        StrictJson.decodeFromString<ClientData>(clientDataJSON.decodeToString())
            .also(ClientData::assertValidity)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is IosHomebrewAttestation) return false

        if (!attestation.contentEquals(other.attestation)) return false
        return clientDataJSON.contentEquals(other.clientDataJSON)
    }

    override fun hashCode(): Int {
        var result = attestation.contentHashCode()
        result = 31 * result + clientDataJSON.contentHashCode()
        return result
    }
}

@Serializable
@SerialName("at.asitplus.signum.indispensable.IosHomebrewAttestation.ClientData")
private data class LegacyClientDataWire(
    val purpose: String,
    @Serializable(with = IosPublicKeySerializer::class)
    val publicKey: PublicKey,
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val challenge: ByteArray,
)

@Serializable
private data class Version2ClientDataWire(
    val purpose: String,
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val publicKey: ByteArray,
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val challenge: ByteArray,
    val version: Int,
)

private fun PublicKey.isLegacyIosKey(): Boolean = when (this) {
    is RsaPublicKey -> true
    is EcdsaPublicKey -> curve.isBuiltIn
    else -> false
}

val Attestation.jsonEncoded: String get() = Json.encodeToString(this)
