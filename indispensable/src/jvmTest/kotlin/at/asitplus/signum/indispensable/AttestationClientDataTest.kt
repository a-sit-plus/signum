package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.io.UVarInt
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

val AttestationClientDataTest by matrixSuite {
    val legacyKey = EcdsaPrivateKey.WithPublicKey(1.toBigInteger(), ECCurve.SECP_256_R_1).publicKey

    "legacy EC client data remains byte-identical" {
        val json = Json.encodeToString(IosHomebrewAttestation.ClientData(legacyKey, byteArrayOf(1, 2)))
        json shouldBe """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","challenge":"AQI"}"""
    }

    "legacy RSA client data remains byte-identical" {
        val rsaKey = RsaPublicKey(("8" + "0".repeat(127)).toBigInteger(16), 65537u)
        val json = Json.encodeToString(IosHomebrewAttestation.ClientData(rsaKey, byteArrayOf(1, 2)))
        json shouldBe """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"MEgCQQCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgMBAAE","challenge":"AQI"}"""
    }

    "v2 uses integer version and SPKI decoding" {
        val spki = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(legacyKey.asn1.toDer())
        val encoded = """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"$spki","challenge":"AwQ","version":2}"""
        val parsed = Json.decodeFromString<IosHomebrewAttestation.ClientData>(encoded)
        parsed.publicKey shouldBe legacyKey
        Json.parseToJsonElement(Json.encodeToString(parsed)).jsonObject.containsKey("version") shouldBe false

        Json.parseToJsonElement(encoded).jsonObject.getValue("version").jsonPrimitive.content shouldBe "2"
    }

    "v2 round trips a key from an externally registered format provider" {
        ServiceLoader.register<Asn1PublicKeyFormatProvider>(ExternalPublicKeyFormatProvider)
        val externalKey = ExternalProviderPublicKey(0x5au)
        val encoded = Json.encodeToString(IosHomebrewAttestation.ClientData(externalKey, byteArrayOf(6)))
        Json.parseToJsonElement(encoded).jsonObject.getValue("version").jsonPrimitive.content shouldBe "2"
        Json.decodeFromString<IosHomebrewAttestation.ClientData>(encoded).publicKey shouldBe externalKey
    }

    "unsupported or non-integer explicit versions are rejected" {
        listOf("1", "3", "\"2\"", "2.0", "null").forEach { version ->
            val json = """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"AQ==","challenge":"AQI","version":$version}"""
            shouldThrow<SerializationException> {
                Json.decodeFromString<IosHomebrewAttestation.ClientData>(json)
            }
        }
        shouldThrow<Throwable> {
            Json.decodeFromString<IosHomebrewAttestation.ClientData>(
                """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"AQI","challenge":"AQI","version":2}"""
            )
        }
    }

    "direct decoder calls honor their Json configuration" {
        val json = """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"${legacyKey.iosEncoded.let { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(it) }}","challenge":"AQI","extra":true}"""
        shouldThrow<SerializationException> {
            Json.decodeFromString<IosHomebrewAttestation.ClientData>(json)
        }
        Json { ignoreUnknownKeys = true }
            .decodeFromString<IosHomebrewAttestation.ClientData>(json).publicKey shouldBe legacyKey
    }

    "attestation retains the received client data bytes" {
        val raw = """ {"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"${legacyKey.iosEncoded.let { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(it) }}","challenge":"AQI"} """.encodeToByteArray()
        val attestation = IosHomebrewAttestation(byteArrayOf(9), raw)
        attestation.parsedClientData.publicKey shouldBe legacyKey
        attestation.clientDataJSON shouldBe raw
    }
}

private data class ExternalProviderPublicKey(val value: UByte) : PublicKey {
    override val sourceRepresentation = SourceRepresentationStorage()
    override val additionalProperties = mutableMapOf<String, String>()
    override val didCodec = UVarInt(0x7fffu)
    override val didKeyBytes: ByteArray get() = byteArrayOf(value.toByte())
}

private object ExternalPublicKeyFormatProvider : Asn1PublicKeyFormatProvider {
    private val oid = ObjectIdentifier("1.3.6.1.4.1.55555.1")

    override fun encodeToAsn1(value: PublicKey): SubjectPublicKeyInfo? =
        (value as? ExternalProviderPublicKey)?.let {
            SubjectPublicKeyInfo(X509AlgorithmIdentifier(oid, Asn1Null), Asn1BitString(it.didKeyBytes))
        }

    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): PublicKey? =
        if (publicKeyInfo.algorithmOid == oid) {
            ExternalProviderPublicKey(publicKeyInfo.subjectPublicKey.bitCarryingBytes.single().toUByte())
        } else null

    override fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): PublicKey? = null
}
