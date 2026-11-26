package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo
import at.asitplus.awesn1.crypto.Sec1EcPublicKeyInfo.Companion.from
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.io.UVarInt
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
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
import java.util.Base64

val AttestationClientDataTest by matrixSuite {
    Signum.installIndispensable()
    ServiceLoader.register<Asn1PublicKeyFormatProvider>(ExternalPublicKeyFormatProvider)
    val legacyKey = EcdsaPrivateKey.WithPublicKey(1.toBigInteger(), ECCurve.SECP_256_R_1).publicKey

    "legacy EC client data remains byte-identical" {
        val publicKeys = listOf(
            "BGsX0fLhLEJH-Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
            "BKqHyiK-iwU3jrHHHvMgrXRuHTtii6ebmFn3QeCCVCo4VQLyXb9VKWw6VF44cnYKtzYX3kqWJixvXZ6Yv5KS3Cn49B29KJoUfOnaMRO18LjACmCxzh1-gZ16Qx18kOoOXw",
            "BADGhY4GtwQE6c2ePstmI5W0QpxkgTkFP7Uh-CivYGtNPbqhS1537-dZKP4dwSei_6jeM0izwYVqQpv5fn4xwuW9ZgEYOSlqeJo7wARcil-0LH0b2Zj1RElXm0RoF6-9Fyc-ZiyX7nKZXvQmQMVQuQE_rQdhNTxwhqJywkCIvpR2n9FmUA",
        )
        ECCurve.entries.zip(publicKeys).forEach { (curve, rawKey) ->
            val key = EcdsaPublicKey(curve.generator, preferCompressedRepresentation = true)
            val clientData = IosHomebrewAttestation.ClientData(key, byteArrayOf(1, 2))
            val json = """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"$rawKey","challenge":"AQI"}"""
            clientData.prepareDigestInput() shouldBe json.encodeToByteArray()
            Json.decodeFromString<IosHomebrewAttestation.ClientData>(json) shouldBe clientData
        }
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
        val externalKey = ExternalProviderPublicKey(0x5au)
        val clientData = IosHomebrewAttestation.ClientData(externalKey, byteArrayOf(6))
        val encoded = Json.encodeToString(clientData)
        Json.parseToJsonElement(encoded).jsonObject.getValue("version").jsonPrimitive.content shouldBe "2"
        Json.decodeFromString<IosHomebrewAttestation.ClientData>(encoded) shouldBe clientData
    }

    "v2 preserves the identity of a custom EC curve with the same size as P-256" {
        val key = EcdsaPublicKey.fromUncompressed(sameSizeCurve, legacyKey.xBytes, legacyKey.yBytes)
        val clientData = IosHomebrewAttestation.ClientData(key, byteArrayOf(6))
        val raw = clientData.prepareDigestInput()
        val json = Json.parseToJsonElement(raw.decodeToString()).jsonObject
        json.getValue("version").jsonPrimitive.isString shouldBe false
        json.getValue("version").jsonPrimitive.content shouldBe "2"
        val attestation = IosHomebrewAttestation(byteArrayOf(9), raw)
        attestation.parsedClientData shouldBe clientData
        val decoded = attestation.parsedClientData.publicKey as EcdsaPublicKey
        (decoded.curve === sameSizeCurve) shouldBe true
        attestation.clientDataJSON shouldBe raw

        val agreementKey: KeyAgreementPublicValue = key
        val decodedAgreementKey = KeyAgreementPublicValue.fromAsn1(agreementKey.asn1.toDer())
        decodedAgreementKey shouldBe key
    }

    "unsupported or non-integer explicit versions are rejected" {
        listOf("1", "3", "\"2\"", "2.0", "null").forEach { version ->
            val json = """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"AQ==","challenge":"AQI","version":$version}"""
            shouldThrow<SerializationException> {
                Json.decodeFromString<IosHomebrewAttestation.ClientData>(json)
            }
        }
        val legacyRawKey = Base64.getUrlEncoder().withoutPadding().encodeToString(legacyKey.iosEncoded)
        shouldThrow<Asn1Exception> {
            Json.decodeFromString<IosHomebrewAttestation.ClientData>(
                """{"purpose":"${IosHomebrewAttestation.THE_PURPOSE}","publicKey":"$legacyRawKey","challenge":"AQI","version":2}"""
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

private val sameSizeCurve = object : ECCurve by ECCurve.SECP_256_R_1 {
    override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.2")
}

private object ExternalPublicKeyFormatProvider : Asn1PublicKeyFormatProvider {
    private val oid = ObjectIdentifier("1.3.6.1.4.1.55555.1")

    override fun encodeToAsn1(value: PublicKey): SubjectPublicKeyInfo? = when (value) {
        is ExternalProviderPublicKey ->
            SubjectPublicKeyInfo(X509AlgorithmIdentifier(oid, Asn1Null), Asn1BitString(value.didKeyBytes))
        is EcdsaPublicKey -> if (value.curve === sameSizeCurve) {
            SubjectPublicKeyInfo.from(Sec1EcPublicKeyInfo.Uncompressed(sameSizeCurve.oid, value.xBytes, value.yBytes))
        } else null
        else -> null
    }

    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): PublicKey? = when (publicKeyInfo.algorithmOid) {
        oid -> ExternalProviderPublicKey(publicKeyInfo.subjectPublicKey.bitCarryingBytes.single().toUByte())
        EcdsaPublicKey.oid -> (Sec1EcPublicKeyInfo.of(publicKeyInfo, Signum.Der) as? Sec1EcPublicKeyInfo.Uncompressed)
            ?.takeIf { it.curveOid == sameSizeCurve.oid }
            ?.let { EcdsaPublicKey.fromUncompressed(sameSizeCurve, it.x, it.y) }
        else -> null
    }

    override fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray): PublicKey? = null
}
