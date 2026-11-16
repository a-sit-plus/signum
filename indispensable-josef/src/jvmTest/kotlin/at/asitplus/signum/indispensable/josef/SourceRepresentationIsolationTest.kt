package at.asitplus.signum.indispensable.josef

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.sourceFormat
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs

val JwsSourceRepresentationIsolationTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    "MAC source ownership" - {
        JwsAlgorithm.MAC.entries.asData(nameFn = { it.identifier }) - { preset ->
            test("Stays source-free after ASN1 HMAC decoding") {
                isolatedScenario(JwsSourceRepresentationScenarios::class.java, "macPreset", preset.identifier)
            }
            test("JSON decoding does not write representation storage") {
                isolatedScenario(JwsSourceRepresentationScenarios::class.java, "macJson", preset.identifier)
            }
        }
    }
    "JSON signature decoding does not write representation storage" - {
        JwsAlgorithm.Signature.entries.asData(nameFn = { it.identifier }) test { preset ->
            isolatedScenario(JwsSourceRepresentationScenarios::class.java, "signatureJson", preset.identifier)
        }
    }
    "PSS encoding survives unrelated ASN1 digest decoding" - {
        listOf("PS256", "PS384", "PS512").asData() test { identifier ->
            isolatedScenario(JwsSourceRepresentationScenarios::class.java, "pssEncoding", identifier)
        }
    }
}

internal object JwsSourceRepresentationScenarios {
    private fun mac(identifier: String) = JwsAlgorithm.MAC.entries.single { it.identifier == identifier }
    private fun signature(identifier: String) = JwsAlgorithm.Signature.entries.single { it.identifier == identifier }

    @JvmStatic
    fun macPreset(identifier: String) {
        val preset = mac(identifier).algorithm as HMAC
        preset.sourceFormat shouldBe "<no source>"
        MessageAuthenticationCode.fromAsn1(X509AlgorithmIdentifier(preset.oid, Asn1Null))

        preset.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun pssEncoding(identifier: String) {
        val preset = signature(identifier).algorithm
        val digest = preset.preHashedSignatureFormat as WellKnownDigest
        val before = preset.asn1.toDer()
        Digest.fromAsn1(X509AlgorithmIdentifier(digest.oid, Asn1Null))

        preset.asn1.toDer() shouldBe before
    }

    @JvmStatic
    fun macJson(identifier: String) {
        val preset = mac(identifier)
        val json = joseCompliantSerializer.encodeToString(JwsAlgorithmSerializer, preset)
        val decoded = joseCompliantSerializer.decodeFromString(JwsAlgorithmSerializer, json)

        decoded shouldBeSameInstanceAs preset
        preset.algorithm.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun signatureJson(identifier: String) {
        val preset = signature(identifier)
        val json = joseCompliantSerializer.encodeToString(JwsAlgorithmSerializer, preset)
        val decoded = joseCompliantSerializer.decodeFromString(JwsAlgorithmSerializer, json)

        decoded shouldBeSameInstanceAs preset
        preset.algorithm.sourceFormat shouldBe "<no source>"
    }
}
