package at.asitplus.signum.indispensable.cosef

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.sourceFormat
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs

val CoseSourceRepresentationIsolationTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    "MAC source ownership" - {
        CoseAlgorithm.MAC.entries.asData(nameFn = { it.coseValue.toString() }) - { preset ->
            test("Stays source-free after ASN1 HMAC decoding") {
                isolatedScenario(CoseSourceRepresentationScenarios::class.java, "macPreset", preset.coseValue.toString())
            }
            test("CBOR decoding does not write representation storage") {
                isolatedScenario(CoseSourceRepresentationScenarios::class.java, "macCbor", preset.coseValue.toString())
            }
        }
    }
    "CBOR signature decoding does not write representation storage" - {
        CoseAlgorithm.Signature.entries.asData(nameFn = { it.coseValue.toString() }) test { preset ->
            isolatedScenario(CoseSourceRepresentationScenarios::class.java, "signatureCbor", preset.coseValue.toString())
        }
    }
    "PSS encoding survives unrelated ASN1 digest decoding" - {
        listOf(-37, -38, -39).asData() test { value ->
            isolatedScenario(CoseSourceRepresentationScenarios::class.java, "pssEncoding", value.toString())
        }
    }
}

internal object CoseSourceRepresentationScenarios {
    private fun mac(value: String) = CoseAlgorithm.MAC.entries.single { it.coseValue.toString() == value }
    private fun signature(value: String) = CoseAlgorithm.Signature.entries.single { it.coseValue.toString() == value }

    @JvmStatic
    fun macPreset(value: String) {
        val preset = mac(value).algorithm
        val hmac = when (preset) {
            is HMAC -> preset
            is MessageAuthenticationCode.Truncated -> preset.inner as HMAC
            else -> error("Unexpected COSE MAC")
        }
        preset.sourceFormat shouldBe "<no source>"
        hmac.sourceFormat shouldBe "<no source>"
        MessageAuthenticationCode.fromAsn1(X509AlgorithmIdentifier(hmac.oid, Asn1Null))

        preset.sourceFormat shouldBe "<no source>"
        hmac.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun pssEncoding(value: String) {
        val preset = signature(value).algorithm
        val digest = preset.preHashedSignatureFormat as WellKnownDigest
        val before = preset.asn1.toDer()
        Digest.fromAsn1(X509AlgorithmIdentifier(digest.oid, Asn1Null))

        preset.asn1.toDer() shouldBe before
    }

    @JvmStatic
    fun macCbor(value: String) {
        val preset = mac(value)
        val bytes = coseCompliantSerializer.encodeToByteArray(CoseAlgorithmSerializer, preset)
        val decoded = coseCompliantSerializer.decodeFromByteArray(CoseAlgorithmSerializer, bytes)

        decoded shouldBeSameInstanceAs preset
        preset.algorithm.sourceFormat shouldBe "<no source>"
        (preset.algorithm as? MessageAuthenticationCode.Truncated)?.inner?.sourceFormat?.shouldBe("<no source>")
    }

    @JvmStatic
    fun signatureCbor(value: String) {
        val preset = signature(value)
        val bytes = coseCompliantSerializer.encodeToByteArray(CoseAlgorithmSerializer, preset)
        val decoded = coseCompliantSerializer.decodeFromByteArray(CoseAlgorithmSerializer, bytes)

        decoded shouldBeSameInstanceAs preset
        preset.algorithm.sourceFormat shouldBe "<no source>"
    }
}
