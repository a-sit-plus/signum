package at.asitplus.signum.supreme.os

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.CertificateChainBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import kotlinx.serialization.SerialInfo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonClassDiscriminator
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@Serializable
@JsonClassDiscriminator("typ")
sealed interface Attestation {
    companion object {
        fun fromJSON(v: String) = Json.decodeFromString<Attestation>(v)
    }
}

@Serializable
@SerialName("android-key")
data class AndroidKeystoreAttestation (
    @Serializable(with=CertificateChainBase64UrlSerializer::class)
    @SerialName("x5c")
    val certificateChain: CertificateChain) : Attestation

@Serializable
@SerialName("ios-appattest-assertion")
data class iosLegacyHomebrewAttestation(
    @Serializable(with=ByteArrayBase64UrlSerializer::class)
    val attestation: ByteArray,
    @Serializable(with=ByteArrayBase64UrlSerializer::class)
    val assertion: ByteArray): Attestation {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is iosLegacyHomebrewAttestation) return false

        if (!attestation.contentEquals(other.attestation)) return false
        return assertion.contentEquals(other.assertion)
    }

    override fun hashCode(): Int {
        var result = attestation.contentHashCode()
        result = 31 * result + assertion.contentHashCode()
        return result
    }
}

@Serializable
@SerialName("ios-appattest")
data class iosHomebrewAttestation(
    @Serializable(with=ByteArrayBase64UrlSerializer::class)
    val attestation: ByteArray,
    @Serializable(with=ByteArrayBase64UrlSerializer::class)
    val clientDataJSON: ByteArray): Attestation {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is iosHomebrewAttestation) return false

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
