package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.sha1WithRSAEncryption
import at.asitplus.awesn1.sha256WithRSAEncryption
import at.asitplus.awesn1.sha384WithRSAEncryption
import at.asitplus.awesn1.sha512WithRSAEncryption
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
            test("Decoding leaves the digest preset without a source") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "digestPreset", digest)
            }
            test("Decoded HMACs retain independent input models") {
                isolatedScenario(SourceRepresentationScenarios::class.java, "hmacSources", digest)
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
            "Cached PSS encoding survives unrelated digest decoding" - {
                listOf("algorithm", "parameters", "mgf1").asData() test { kind ->
                    isolatedScenario(SourceRepresentationScenarios::class.java, "cachedPssEncoding", digest, kind)
                }
            }
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

        first.asn1.toRepresentation() shouldBe withNull
        second.asn1.toRepresentation() shouldBe withoutParameters
    }

    @JvmStatic
    fun digestPreset(name: String) {
        val preset = digest(name)
        preset.sourceFormat shouldBe "<no source>"
        val before = preset.asn1.toDer()
        Digest.fromAsn1(X509AlgorithmIdentifier(preset.oid, Asn1Null))

        preset.sourceFormat shouldBe "<no source>"
        preset.asn1.toDer() shouldBe before
    }

    @JvmStatic
    fun hmacSources(name: String) {
        val preset = HMAC.byDigest(digest(name))
        // HMAC only accepts NULL parameters, so use equal but separately owned input models.
        val firstModel = X509AlgorithmIdentifier(preset.oid, Asn1Null)
        val secondModel = X509AlgorithmIdentifier(preset.oid, Asn1Null)
        firstModel shouldNotBeSameInstanceAs secondModel
        val first = MessageAuthenticationCode.fromAsn1(firstModel)
        val second = MessageAuthenticationCode.fromAsn1(secondModel)

        first.asn1.toRepresentation() shouldBeSameInstanceAs firstModel
        second.asn1.toRepresentation() shouldBeSameInstanceAs secondModel
    }

    @JvmStatic
    fun hmacPreset(name: String) {
        val preset = HMAC.byDigest(digest(name))
        preset.sourceFormat shouldBe "<no source>"
        MessageAuthenticationCode.fromAsn1(X509AlgorithmIdentifier(preset.oid, Asn1Null))

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
    fun cachedPssEncoding(name: String, kind: String) {
        val preset = pss(name)
        val algorithm = RsaAlgorithm.entries.single { it.digest.name == name && it.parameters is PssPadded }
        fun encode() = when (kind) {
            "algorithm" -> algorithm.asn1.toDer()
            "parameters" -> preset.asn1.toDer()
            "mgf1" -> preset.mgfAlgorithm.asn1.toDer()
            else -> error(kind)
        }
        val before = encode()
        Digest.fromAsn1(X509AlgorithmIdentifier(digest(name).oid, Asn1Null))

        encode() shouldBe before
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
        val preset = Name.EMPTY
        Name.fromString("") shouldBeSameInstanceAs preset
        val first = Name.fromAsn1("3000".hexToByteArray())
        val second = Name.fromAsn1("3000".hexToByteArray())

        first shouldBe preset
        first.sourceRepresentation shouldNotBeSameInstanceAs preset.sourceRepresentation
        first.sourceRepresentation shouldNotBeSameInstanceAs second.sourceRepresentation
        preset.sourceFormat shouldBe "<no source>"
        preset.asn1.toDer() shouldBe "3000".hexToByteArray()
    }
}
