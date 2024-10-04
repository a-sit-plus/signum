package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.CertificateChainBase64UrlSerializer
import at.asitplus.signum.indispensable.io.IosPublicKeySerializer
import at.asitplus.signum.indispensable.io.X509CertificateBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
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
    val certificate: X509Certificate) : Attestation

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

    @Serializable
    @ConsistentCopyVisibility
    data class ClientData private constructor(
        private val purpose: String,
        @Serializable(with=IosPublicKeySerializer::class)
        val publicKey: CryptoPublicKey,
        @Serializable(with=ByteArrayBase64UrlSerializer::class)
        val challenge: ByteArray
    ) {
        constructor(publicKey: CryptoPublicKey, challenge: ByteArray) :
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

val Attestation.jsonEncoded: String get() = Json.encodeToString(this)
