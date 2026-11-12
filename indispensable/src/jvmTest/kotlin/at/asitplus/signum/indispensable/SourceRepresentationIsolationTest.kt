package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Parameters.PssPadded
import at.asitplus.signum.indispensable.sign.RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.signum.indispensable.sign.fromAsn1
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.kotest.matchers.types.shouldNotBeSameInstanceAs

val SourceRepresentationIsolationTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    "Digest and HMAC sources" - {
        listOf("SHA1", "SHA256", "SHA384", "SHA512").asData() - { digest ->
            test("Decoded digests retain independent input representations") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "digestSources", digest)
            }
            test("Decoding leaves the HMAC preset without a source") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "hmacPreset", digest)
            }
            test("PSS hash and MGF1 hash retain their distinct representations") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "pssDigestPositions", digest)
            }
            test("PKCS1 parameter preset is not used as decoded storage") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "pkcs1Preset", digest)
            }
        }
    }
    "Cached signature presets" - {
        listOf("SHA256", "SHA384", "SHA512").asData() - { digest ->
            test("ECDSA preset is not used as decoded storage") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "ecdsaPreset", digest)
            }
            "RSA preset is not used as decoded storage" - {
                listOf("PKCS1", "PSS").asData() test { padding ->
                    isolatedScenario(SourceRepresentationScenarios::class.java, "rsaPreset", digest, padding)
                }
            }
            test("PSS parameter and MGF1 presets are not used as decoded storage") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "pssPreset", digest)
            }
        }
    }
    test("Parsing empty names leaves Name.EMPTY without a source") {
        isolatedScenario(SourceRepresentationScenarios::class.java, "emptyName")
    }
}

internal object SourceRepresentationScenarios {
    private fun digest(name: String) = WellKnownDigest.entries.single { it.name == name }

    @JvmStatic
    fun digestSources(name: String) {
        val preset = digest(name)
        val withNull = X509AlgorithmIdentifier(preset.oid, Asn1Null)
        val withoutParameters = X509AlgorithmIdentifier(preset.oid, null)
        val first = Digest.fromAsn1(withNull)
        val second = Digest.fromAsn1(withoutParameters)

        preset.asn1.toRepresentation() shouldNotBeSameInstanceAs withoutParameters
        first.asn1.toRepresentation() shouldBe withNull
        second.asn1.toRepresentation() shouldBe withoutParameters
    }

    @JvmStatic
    fun hmacPreset(name: String) {
        val preset = HMAC.byDigest(digest(name))
        preset.sourceFormat shouldBe "<no source>"
        val _ = MessageAuthenticationCode.fromAsn1(X509AlgorithmIdentifier(preset.oid, Asn1Null))

        preset.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun pssDigestPositions(name: String) {
        val preset = digest(name)
        val withNull = X509AlgorithmIdentifier(preset.oid, Asn1Null)
        val withoutParameters = X509AlgorithmIdentifier(preset.oid, null)
        val model = RsaSsaPssParams(
            hashAlgorithm = withNull,
            maskGenAlgorithm = X509AlgorithmIdentifier(Pkcs1Mgf1.oid, withoutParameters.element),
            saltLength = preset.outputLength.bytes.toInt(),
        )
        val parsed = PssPadded.fromAsn1(model)

        parsed.digest.asn1.toRepresentation() shouldBe withNull
        (parsed.mgfAlgorithm as Pkcs1Mgf1).digest.asn1.toRepresentation() shouldBe withoutParameters
    }

    private fun pss(name: String) = when (name) {
        "SHA256" -> PssPadded.DEFAULT_SHA256
        "SHA384" -> PssPadded.DEFAULT_SHA384
        "SHA512" -> PssPadded.DEFAULT_SHA512
        else -> error(name)
    }

    @JvmStatic
    fun ecdsaPreset(name: String) {
        val preset = EcdsaAlgorithm.entries.single { it.digest?.name == name }
        val model = preset.asn1.toRepresentation()
        val first = EcdsaAlgorithm.fromAsn1(model)
        val second = EcdsaAlgorithm.fromAsn1(model)

        first.sourceRepresentation shouldNotBeSameInstanceAs preset.sourceRepresentation
        first.sourceRepresentation shouldNotBeSameInstanceAs second.sourceRepresentation
        first.asn1.toRepresentation() shouldBe model
        preset.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun rsaPreset(name: String, padding: String) {
        val preset = RsaAlgorithm.entries.single { it.digest.name == name && it.parameters.type.name == padding }
        val model = preset.asn1.toRepresentation()
        val first = RsaAlgorithm.fromAsn1(model)
        val second = RsaAlgorithm.fromAsn1(model)

        first.sourceRepresentation shouldNotBeSameInstanceAs preset.sourceRepresentation
        first.sourceRepresentation shouldNotBeSameInstanceAs second.sourceRepresentation
        first.parameters.sourceRepresentation shouldNotBeSameInstanceAs preset.parameters.sourceRepresentation
        first.asn1.toRepresentation() shouldBe model
        preset.sourceFormat shouldBe "<no source>"
        preset.parameters.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun pkcs1Preset(name: String) {
        val preset = RsaAlgorithm.Parameters.Pkcs1Padded.entries.single { it.digest.name == name }
        val oid = when (name) {
            "SHA1" -> KnownOIDs.sha1WithRSAEncryption
            "SHA256" -> KnownOIDs.sha256WithRSAEncryption
            "SHA384" -> KnownOIDs.sha384WithRSAEncryption
            "SHA512" -> KnownOIDs.sha512WithRSAEncryption
            else -> error(name)
        }
        val decoded = RsaAlgorithm.fromAsn1(X509AlgorithmIdentifier(oid, Asn1Null)).parameters

        decoded.sourceRepresentation shouldNotBeSameInstanceAs preset.sourceRepresentation
        preset.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun pssPreset(name: String) {
        val preset = pss(name)
        val model = preset.asn1.toRepresentation()
        val decoded = PssPadded.fromAsn1(model)

        decoded.sourceRepresentation shouldNotBeSameInstanceAs preset.sourceRepresentation
        decoded.mgfAlgorithm.sourceRepresentation shouldNotBeSameInstanceAs preset.mgfAlgorithm.sourceRepresentation
        decoded.asn1.toRepresentation() shouldBe model
        preset.sourceFormat shouldBe "<no source>"
        preset.mgfAlgorithm.sourceFormat shouldBe "<no source>"
    }

    @JvmStatic
    fun emptyName() {
        val emptySingleton = Name.EMPTY
        Name.fromString("") shouldBeSameInstanceAs emptySingleton
        val tlv1 = Asn1Element.parseFromDerHexString("3000")
        val tlv2 = Asn1Element.parseFromDerHexString("3000")
        tlv1 shouldNotBeSameInstanceAs tlv2
        val first = Name.fromAsn1(tlv1)
        val second = Name.fromAsn1(tlv2)

        first shouldBe emptySingleton
        second shouldBe emptySingleton
        first.asn1.toRepresentation() shouldBeSameInstanceAs tlv1
        second.asn1.toRepresentation() shouldBeSameInstanceAs tlv2
        emptySingleton.sourceFormat shouldBe "<no source>"
        emptySingleton.asn1.toDer() shouldBe "3000".hexToByteArray()
    }
}
