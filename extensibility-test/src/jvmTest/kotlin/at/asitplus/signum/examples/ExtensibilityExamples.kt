package at.asitplus.signum.examples

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as WireExtension
import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.Signum
// --8<-- [start:migration-current-imports]
import at.asitplus.signum.dsl.*
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.*
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.*
// --8<-- [end:migration-current-imports]
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.supreme.sign.CursorySignatureScheme
import at.asitplus.signum.supreme.sign.CursorySignatureSchemeProvider
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.modules.SerializersModule

// --8<-- [start:extension-digest]
// Educational checksum: this deliberately has no cryptographic security.
object ByteSum : Digest {
    override val name = "Example byte sum"
    override val inputBlockSize = 8.bit
    override val outputLength = 8.bit
    override val sourceRepresentation: Pair<Encodable.Representation, Any>? = null
    val identifier = X509AlgorithmIdentifier(ObjectIdentifier("1.3.6.1.4.1.55555.1"), null)
}

object ByteSumProvider : DigestProvider, DigestOperationProvider {
    override fun getDigest(algorithmIdentifier: X509AlgorithmIdentifier): Digest? =
        ByteSum.takeIf { algorithmIdentifier == ByteSum.identifier }
    override fun encodeToAsn1(value: Digest): X509AlgorithmIdentifier? =
        ByteSum.identifier.takeIf { value === ByteSum }
    override suspend fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray? {
        if (digest !== ByteSum) return null // Let the next provider try.
        var sum = 0
        data.forEach { chunk -> chunk.forEach { sum += it.toInt() and 255 } }
        return byteArrayOf(sum.toByte())
    }
}
// --8<-- [end:extension-digest]

// --8<-- [start:extension-serializers]
val exampleSerializers = SerializersModule {
    contextualAsn1(ByteSum::class, X509AlgorithmIdentifier.serializer(),
        toModel = { ByteSum.identifier },
        fromModel = { require(it == ByteSum.identifier); ByteSum })
}
// --8<-- [end:extension-serializers]

// --8<-- [start:extension-descriptor]
// A private extension carrying one byte; malformed registered data is rejected.
class ExampleFlag private constructor(source: Pair<Encodable.Representation, Any>?, enabled: Boolean, critical: Boolean) :
    X509CertificateExtension(source, oid, critical, byteArrayOf(if (enabled) 1 else 0)) {
    val enabled: Boolean get() = derEncodedValue[0] == 1.toByte()
    constructor(enabled: Boolean) : this(null, enabled, false)
    companion object : CertificateExtension.Descriptor<ExampleFlag> {
        override val oid = ObjectIdentifier("1.3.6.1.4.1.55555.2")
        override fun fromAsn1Representation(src: WireExtension): ExampleFlag {
            require(src.oid == oid)
            require(src.value.size == 1 && src.value[0] in byteArrayOf(0, 1))
            return ExampleFlag(X509 to src, src.value[0] == 1.toByte(), src.critical)
        }
    }
}
// --8<-- [end:extension-descriptor]

// --8<-- [start:extension-dsl]
class ExampleOptions : DSL.Data() {
    var label = "default"
    class Details : DSL.Data() { var enabled = false }
}
val InMemorySignerConfiguration.example get() =
    childOrDefault("at.asitplus.signum.examples.options", ::ExampleOptions)
val ExampleOptions.details get() = childOrDefault("details", ExampleOptions::Details)

class ExampleAlgorithmOptions : EphemeralSignerConfiguration.AlgorithmSpecific() {
    var keyBit = true
}
val EphemeralSignerConfiguration.exampleAlgorithm get() =
    _algSpecific.option("at.asitplus.signum.examples.algorithm", ::ExampleAlgorithmOptions)
// --8<-- [end:extension-dsl]

// --8<-- [start:extension-dsl-provider]
object ExampleKeysProvider : InMemoryKeysProvider {
    override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration): Signer.WithExportableKey? {
        val options = config.exampleAlgorithm.v ?: return null
        return CursorySignatureScheme.Key(options.keyBit)
    }
    override fun createSignerForKey(algorithm: SignatureAlgorithm,
        privateKey: CryptoPrivateKey.WithPublicKey, config: InMemorySignerConfiguration): Signer.WithExportableKey? =
        CursorySignatureSchemeProvider.createSignerForKey(algorithm, privateKey, config)
}
// --8<-- [end:extension-dsl-provider]

// --8<-- [start:extension-override-provider]
object ExampleDigestOverride : DigestOperationProvider {
    override suspend fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray? {
        if (digest !== ByteSum) return null
        val chunks = data.toList()
        // Change this input only, so other checksum examples remain independent.
        return if (chunks.size == 1 && chunks.single().contentEquals(byteArrayOf(99))) byteArrayOf(42)
        else ByteSumProvider.doDigest(digest, chunks.asSequence())
    }
}

fun installExampleOverride() {
    Signum.registerProvider<DigestOperationProvider>(ExampleDigestOverride)
}
// --8<-- [end:extension-override-provider]

// --8<-- [start:extension-bootstrap]
fun bootstrapExamples() {
    Signum.setDer(DER { maxNestingDepth = 80 }) /* (1)! */
    Signum.installSupreme()
    CursorySignatureSchemeProvider.install()
    Signum.register(ByteSumProvider, serializers = exampleSerializers) /* (2)! */
    Signum.register(ExampleFlag) /* (3)! */
    Signum.registerProvider<InMemoryKeysProvider>(ExampleKeysProvider)
    Signum.Der /* (4)! */
    installExampleOverride() // Provider-only registration is still allowed.
}
// --8<-- [end:extension-bootstrap]

val ExtensibilityExamples by matrixSuite {
    "Unexpected signing failure propagates" {
        // --8<-- [start:migration-current-signing-result]
        val failure = shouldThrow<IllegalStateException> {
            SignatureResult.make<CryptoSignature> { error("Failed") }
        }
        failure.message shouldBe "Failed"
        val cancelled = UserInitiatedCancellation("Cancelled", null)
        val result = SignatureResult.make<CryptoSignature> { throw cancelled }
        (result as SignatureResult.Failure).problem shouldBe cancelled
        // --8<-- [end:migration-current-signing-result]
    }

    "Checksum, concrete serializer and fallback" {
        ByteSum.digest(byteArrayOf(1, 2, 3)).toList() shouldBe listOf(6.toByte())
        Signum.Der.decodeFromByteArray<ByteSum>(Signum.Der.encodeToByteArray(ByteSum)) shouldBe ByteSum
        Digest.fromAsn1Representation(ByteSum.identifier) shouldBe ByteSum
        Digest.SHA256.digest(byteArrayOf()).size shouldBe 32
    }
    "Descriptor round trip and malformed body" {
        val flag = ExampleFlag(true)
        flag.sourceRepresentation shouldBe null
        val decoded = Signum.Der.decodeFromByteArray<ExampleFlag>(Signum.Der.encodeToByteArray(flag))
        decoded.enabled shouldBe true
        decoded shouldBe flag
        decoded.hashCode() shouldBe flag.hashCode()
        decoded.sourceRepresentation!!.first shouldBe X509
        flag.sourceRepresentation shouldBe null
        CertificateExtension.fromAsn1Representation(decoded.asn1Representation) shouldBe decoded
        shouldThrow<IllegalArgumentException> {
            CertificateExtension.fromAsn1Representation(WireExtension(ExampleFlag.oid, false, byteArrayOf(2)))
        }
    }
    "DSL options and nested children" {
        // --8<-- [start:extension-dsl-use]
        val config = DSL.resolve(::EphemeralSignerConfiguration) {
            exampleAlgorithm { keyBit = false }
            example { label = "selected"; details { enabled = true } }
        }
        config.exampleAlgorithm.v!!.keyBit shouldBe false
        config.example.v.label shouldBe "selected"
        config.example.v.details.v.enabled shouldBe true
        val signer = Signer.Ephemeral { exampleAlgorithm { keyBit = false } }
        signer.publicKey shouldBe CursorySignatureScheme.Key(false)
        @OptIn(SecretExposure::class)
        val exported = signer.exportPrivateKey()
        val restored = ExampleKeysProvider.createSignerForKey(signer.signatureAlgorithm, exported, InMemorySignerConfiguration())!!
        restored.publicKey shouldBe signer.publicKey
        // --8<-- [end:extension-dsl-use]
    }
    "Provider priority and unsupported fallback" {
        // --8<-- [start:extension-provider-precedence]
        Signum.load<DigestOperationProvider>().first() shouldBe ExampleDigestOverride
        ByteSum.digest(byteArrayOf(99)).toList() shouldBe listOf(42.toByte())
        ExampleDigestOverride.doDigest(Digest.SHA256, sequenceOf(byteArrayOf(1))) shouldBe null
        // --8<-- [end:extension-provider-precedence]
    }
    "Current encoding" {
        // --8<-- [start:migration-current-encoding]
        val signer = Signer.Ephemeral { ec {} }
        val bytes = Signum.Der.encodeToByteArray(signer.publicKey)
        val decoded = Signum.Der.decodeFromByteArray<CryptoPublicKey>(bytes)
        decoded shouldBe signer.publicKey
        Signum.Der.encodeToByteArray(decoded).toList() shouldBe bytes.toList()
        // --8<-- [end:migration-current-encoding]
    }
}
