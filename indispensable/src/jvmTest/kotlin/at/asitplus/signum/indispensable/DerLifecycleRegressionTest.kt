package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.sha_256
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.sign.EcdsaSignature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import java.io.File
import java.lang.reflect.InvocationTargetException
import java.net.URLClassLoader

val DerLifecycleRegressionTest by matrixSuite {
    "Decoding a digest retains each input representation independently" {
        isolatedDerScenario("digestSources")
    }

    "Signum can reuse the default DER after awesn1 has initialized it" {
        isolatedDerScenario("defaultDerBeforeSignum")
    }

    "Nested ECDSA decoding respects the selected input length limit" {
        isolatedDerScenario("nestedDecodingLimit")
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

    @JvmStatic
    fun defaultDerBeforeSignum() {
        val defaultDer = DER

        Signum.Der shouldBeSameInstanceAs defaultDer
    }

    @JvmStatic
    fun nestedDecodingLimit() {
        Signum.setDer(DER { maxInputLength = 1 })

        shouldThrowAny {
            EcdsaSignature.fromRawSignatureValue("3006020101020102".hexToByteArray())
        }
    }
}
