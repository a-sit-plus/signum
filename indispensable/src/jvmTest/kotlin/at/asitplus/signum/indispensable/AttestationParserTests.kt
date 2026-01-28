package at.asitplus.signum.indispensable

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import kotlinx.serialization.json.*
import java.io.ByteArrayInputStream
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.*

private val certificateFactory = CertificateFactory.getInstance("X.509")

val CustomParserTests by testSuite {
    val chain: Map<String, JsonObject> by lazy {
        val json = Json { ignoreUnknownKeys = true }
        val classLoader = Thread.currentThread().contextClassLoader

        fun listResourceJsonFiles(resourceDir: String): List<Path> {
            val url = classLoader.getResource(resourceDir)
                ?: error("Missing test resources directory '$resourceDir' on the classpath")

            val uri = url.toURI()
            return when (uri.scheme) {
                "jar" -> FileSystems.newFileSystem(uri, emptyMap<String, Any>()).use { fs ->
                    val root = fs.getPath(resourceDir)
                    Files.list(root).use { stream ->
                        stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".json") }
                            .sorted()
                            .toList()
                    }
                }

                else -> {
                    val root = Paths.get(uri)
                    Files.list(root).use { stream ->
                        stream.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".json") }
                            .sorted()
                            .toList()
                    }
                }
            }
        }

        val paths = listResourceJsonFiles("attestation-results").also { it.shouldNotBeEmpty() }
        paths.associate { path ->

            val text = Files.readString(path).also { it.shouldNotBeBlank() }
            path.fileName.toString() to json.parseToJsonElement(text).jsonObject
        }
    }

    "fixtures are present" {
        chain.size shouldBeGreaterThan 0
        chain.forEach { (_, json) -> json.isNotEmpty() shouldBe true }
    }

    withData(chain) {
        val chain = it.getValue("attestationProof").jsonArray.map {
            Base64.getMimeDecoder().decode(it.jsonPrimitive.content.replace("\n", ""))
        }
        val attestationCertChain =
            chain.map { certificateFactory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate }

        attestationCertChain.forEachIndexed { index, certificate ->

            withClue(index.toString()) {
                certificate.toKmpCertificate().getOrThrow().encodeToDer() shouldBe certificate.encoded
            }
        }
    }
}
