package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.Pkcs1RsaPublicKeyInfo.Companion.from
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.DefaultDer
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.pki.CertificateExtension
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.signum.indispensable.sign.RsaPrivateKey
import at.asitplus.signum.indispensable.sign.RsaPublicKey
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.signum.indispensable.sign.fromAsn1
import at.asitplus.testballoon.matrix.ExecutionMode
import at.asitplus.testballoon.matrix.matrixConfig
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.kotest.matchers.types.shouldNotBeSameInstanceAs
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.modules.SerializersModule
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.net.URLClassLoader
import java.security.KeyPairGenerator

val DerLifecycleRegressionTest by matrixSuite(matrixConfig { execution = ExecutionMode.Sequential }) {
    test("Decoding a digest retains each input representation independently") {
        isolatedDerScenario("digestSources")
    }

    //working as intended. not a bug Leaving it here as a memento
    /*test("Signum can reuse the default DER after awesn1 has initialized it") {
        isolatedDerScenario("defaultDerBeforeSignum")
    }*/

    test("Signum copies the default DER template after awesn1 has used it") {
        isolatedDerScenario("defaultDerTemplateAfterUse")
    }

    "Nested DER codecs" - {
        test("ECDSA parsing respects the selected input length limit") {
            isolatedDerScenario("nestedDecodingLimit")
        }
        test("RSA public key parsing respects the selected input length limit") {
            isolatedDerScenario("rsaNestedDecodingLimit")
        }
        test("ECDSA encoding and parsing leave the default DER uninitialized") {
            isolatedDerScenario("ecdsaCustomDerRoundTrip")
        }
        test("RSA public key encoding and parsing leave the default DER uninitialized") {
            isolatedDerScenario("rsaCustomDerRoundTrip")
        }
        test("RSA PKCS1 private key parsing leaves the default DER uninitialized") {
            isolatedDerScenario("rsaPrivateKeyCustomDerRoundTrip")
        }
        test("CSR extension encoding and parsing leave the default DER uninitialized") {
            isolatedDerScenario("csrExtensionsCustomDerRoundTrip")
        }
    }
}

// Each scenario starts with fresh Signum and awesn1 globals, independent of the test session.
private fun isolatedDerScenario(name: String) {
    val scenarioClass = DerLifecycleRegressionScenarios::class.java
    val urls = System.getProperty("java.class.path").split(File.pathSeparator)
        .map { File(it).toURI().toURL() }.toTypedArray()
    URLClassLoader(urls, ClassLoader.getPlatformClassLoader()).use { loader ->
        try {
            loader.loadClass(scenarioClass.name).getMethod(name).invoke(null)
        } catch (exception: InvocationTargetException) {
            throw exception.targetException
        }
    }
}

internal object DerLifecycleRegressionScenarios {
    @JvmStatic
    fun digestSources() {
        val withNull = X509AlgorithmIdentifier(KnownOIDs.sha_256, Asn1Null)
        val withoutParameters = X509AlgorithmIdentifier(KnownOIDs.sha_256, null)
        val first = Digest.fromAsn1(withNull)
        val second = Digest.fromAsn1(withoutParameters)

        first.asn1.toRepresentation() shouldBe withNull
        second.asn1.toRepresentation() shouldBe withoutParameters
    }

    //working as intended. not a bug. Signum cioies it over and uses DefaultDer as a template to do its own
    /*@JvmStatic
    fun defaultDerBeforeSignum() {
        val defaultDer = DER

        Signum.Der shouldBeSameInstanceAs defaultDer
    }*/

    @JvmStatic
    fun defaultDerTemplateAfterUse() {
        DefaultDer.maxInputLength = 8
        val inheritedSerializer = Asn1IntegerHexStringSerializer
        DefaultDer.register(SerializersModule {
            contextual(Asn1Integer::class, inheritedSerializer)
        })
        val defaultDer = DER
        val model = EcdsaSigValue(Asn1Integer.ONE, Asn1Integer(2))
        val bytes = defaultDer.encodeToByteArray(model)
        defaultDer.decodeFromDer<EcdsaSigValue>(bytes) shouldBe model
        shouldThrow<IllegalStateException> { DefaultDer.register(SerializersModule {}) }

        val contributedSerializer = X509SignatureValue.serializer()
        Signum.registerAsn1Serializers(SerializersModule {
            contextual(X509SignatureValue::class, contributedSerializer)
        })
        val signature = EcdsaSignature.fromRawSignatureValue(bytes)
        signature.r shouldBe BigInteger.ONE
        signature.s shouldBe BigInteger.TWO
        signature.asn1.toRepresentation().rawBytes shouldBe bytes

        val signumDer = Signum.Der
        signumDer shouldNotBeSameInstanceAs defaultDer
        Signum.Der shouldBeSameInstanceAs signumDer
        signumDer.configuration.copy(serializersModule = defaultDer.serializersModule) shouldBe defaultDer.configuration
        signumDer.serializersModule.getContextual(Asn1Integer::class) shouldBeSameInstanceAs inheritedSerializer
        signumDer.serializersModule.getContextual(X509SignatureValue::class) shouldBeSameInstanceAs contributedSerializer
        defaultDer.serializersModule.getContextual(X509SignatureValue::class) shouldBe null
        signumDer.decodeFromDer<EcdsaSigValue>(bytes) shouldBe model
        shouldThrow<IllegalStateException> { Signum.registerAsn1Serializers(SerializersModule {}) }

        val oversized = "300702020080020102".hexToByteArray()
        shouldThrow<SerializationException> {
            defaultDer.decodeFromDer<EcdsaSigValue>(oversized)
        }.message shouldContain "(limit = 8)"
        shouldThrow<Asn1Exception> {
            EcdsaSignature.fromRawSignatureValue(oversized)
        }.message shouldContain "(limit = 8)"
    }

    @JvmStatic
    fun nestedDecodingLimit() {
        Signum.setDer(DER { maxInputLength = 1 })

        shouldThrow<Asn1Exception> {
            EcdsaSignature.fromRawSignatureValue("3006020101020102".hexToByteArray())
        }.message shouldContain "(limit = 1)"
    }

    @JvmStatic
    fun rsaNestedDecodingLimit() {
        Signum.setDer(DER { maxInputLength = 1 })
        val key = rsaPublicKey()
        val representation = SubjectPublicKeyInfo.from(Pkcs1RsaPublicKeyInfo(key.n, key.e), Signum.Der)

        shouldThrow<Asn1Exception> {
            RsaPublicKey.fromAsn1(representation)
        }.message shouldContain "(limit = 1)"
    }

    @JvmStatic
    fun ecdsaCustomDerRoundTrip() {
        Signum.setDer(DER {})
        val signature = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        val representation = signature.asn1.toRepresentation()

        representation.rawBytes shouldBe "3006020101020102".hexToByteArray()
        EcdsaSignature.fromRawSignatureValue(representation.rawBytes) shouldBe signature
        EcdsaSignature.fromAsn1(signature.asn1.toDer()) shouldBe signature

        //we never touched awens1's DefaultDer
        shouldNotThrowAny { DefaultDer.register(SerializersModule {}) }
    }

    @JvmStatic
    fun rsaCustomDerRoundTrip() {
        Signum.setDer(DER {})
        val key = rsaPublicKey()

        RsaPublicKey.fromAsn1(key.asn1.toRepresentation()) shouldBe key
        RsaPublicKey.fromAsn1(key.asn1.toDer()) shouldBe key

        //we never touched awens1's DefaultDer
        shouldNotThrowAny { DefaultDer.register(SerializersModule {}) }
    }

    @JvmStatic
    fun rsaPrivateKeyCustomDerRoundTrip() {
        Signum.setDer(DER {})
        val encoded = KeyPairGenerator.getInstance("RSA").apply { initialize(512) }.generateKeyPair().private.encoded
        val pkcs8 = Signum.Der.decodeFromDer<Pkcs8PrivateKeyInfo>(encoded)
        val pkcs1 = Pkcs1RsaPrivateKeyInfo.of(pkcs8, Signum.Der)
        val key = RsaPrivateKey.fromAsn1.PKCS1(pkcs1)

        key.asn1.pkcs1.toRepresentation() shouldBe pkcs1
        RsaPrivateKey.fromAsn1.PKCS1(key.asn1.pkcs1.toDer()).asn1.pkcs1.toRepresentation() shouldBe pkcs1

        //we never touched awens1's DefaultDer
        shouldNotThrowAny { DefaultDer.register(SerializersModule {}) }
    }

    @JvmStatic
    fun csrExtensionsCustomDerRoundTrip() {
        Signum.setDer(DER {})
        val extension = CertificateExtension(ObjectIdentifier("1.2.3.4"), value = "0500".hexToByteArray())
        val csr = TbsCertificationRequest(Name.EMPTY, rsaPublicKey(), extensions = listOf(extension))

        csr.extensions.map { it.asn1.toRepresentation() } shouldBe listOf(extension.asn1.toRepresentation())
        val parsed = TbsCertificationRequest.fromAsn1(csr.asn1.toDer())
        parsed.extensions.map { it.asn1.toRepresentation() } shouldBe listOf(extension.asn1.toRepresentation())

        //we never touched awens1's DefaultDer
        shouldNotThrowAny { DefaultDer.register(SerializersModule {}) }
    }

    private fun rsaPublicKey() = RsaPublicKey(
        n = Asn1Integer.fromUnsignedByteArray(ByteArray(64).apply {
            this[0] = 0x80.toByte()
            this[lastIndex] = 1
        }),
        e = Asn1Integer(65537),
    )
}
