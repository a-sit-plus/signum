package at.asitplus.signum.supreme.os

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.pki.CertificateChain
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

sealed interface Attestation {
    val jsonEncoded: String
}

data class AndroidKeystoreAttestation (val certificateChain: CertificateChain) : Attestation {
    @OptIn(ExperimentalEncodingApi::class)
    override val jsonEncoded: String by lazy {
        Json.encodeToString(buildJsonObject {
            put("fmt", "android-key")
            putJsonArray("x5c") {
                certificateChain.forEach { add(Base64.UrlSafe.encode(it.encodeToDer())) }
            }
        })
    }
}

@Serializable
data class iosHomebrewAttestation(
    // TODO document this
    @Serializable(ByteArrayBase64UrlSerializer::class)
    val attestation: ByteArray,
    @Serializable(ByteArrayBase64UrlSerializer::class)
    val assertion: ByteArray): Attestation {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is iosHomebrewAttestation) return false

        if (!attestation.contentEquals(other.attestation)) return false
        return assertion.contentEquals(other.assertion)
    }

    override fun hashCode(): Int {
        var result = attestation.contentHashCode()
        result = 31 * result + assertion.contentHashCode()
        return result
    }

    @OptIn(ExperimentalEncodingApi::class)
    override val jsonEncoded: String by lazy {
        Json.encodeToString(buildJsonObject {
            put("fmt", "ios-appattest-assertion")
            put("attestation", Base64.UrlSafe.encode(attestation))
            put("assertion", Base64.UrlSafe.encode(assertion))
        })
    }
}
