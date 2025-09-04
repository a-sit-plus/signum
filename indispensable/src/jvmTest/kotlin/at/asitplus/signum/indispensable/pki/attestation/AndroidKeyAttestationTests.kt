@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.attestation.android.exceptions.AttestationValueException
import at.asitplus.signum.indispensable.toJcaCertificateBlocking
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.util.encoders.Base64
import org.opentest4j.TestAbortedException
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.*
import kotlin.io.encoding.ExperimentalEncodingApi
import at.asitplus.signum.indispensable.pki.X509Certificate as SigNumX509


@OptIn(ExperimentalStdlibApi::class)
class AndroidKeyAttestationTests : FreeSpec({

    @Serializable
    data class AppPkg(
        val name: String,
        val version: String? = null
    )

    @Serializable
    data class RootOfTrust(
        val verifiedBootState: String? = null,
        val deviceLocked: Boolean? = null,
    )

    @Serializable
    data class HardwareEnforced(
        val rootOfTrust: RootOfTrust? = null
    )

    @Serializable
    data class AttestationApplicationId(
        val packages: List<AppPkg> = emptyList(),
        val signatures: List<String> = emptyList() // base64 digests
    )

    @Serializable
    data class SoftwareEnforced(
        val creationDateTime: String, // millis as string
        val attestationApplicationId: AttestationApplicationId
    )

    @Serializable
    data class AttestationJson(
        val attestationChallenge: String,
        val attestationSecurityLevel: String,
        val keyMintSecurityLevel: String,
        val softwareEnforced: SoftwareEnforced? = null,
        val hardwareEnforced: HardwareEnforced? = null
    )

    fun readResourceDir(dir: String): Path {
        val url = checkNotNull(javaClass.classLoader.getResource(dir)) {
            "Resource directory not found: $dir"
        }
        return Paths.get(url.toURI())
    }

    fun readString(p: Path): String = Files.readString(p, StandardCharsets.UTF_8)

    fun loadPemChain(pemText: String): List<X509Certificate> {
        val re = Regex(
            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.MULTILINE)
        )
        return re.findAll(pemText).map { m ->
            SigNumX509.decodeFromPem(m.value).getOrThrow().toJcaCertificateBlocking().getOrThrow()
        }.toList()
    }

    fun mapSecurityLevel(keymasterLevel: String, attestationLevel: String): AttestationData.Level =
        if (keymasterLevel != attestationLevel) AttestationData.Level.NOUGAT
        else when (keymasterLevel.uppercase()) {
            "SOFTWARE" -> AttestationData.Level.SOFTWARE
            else -> AttestationData.Level.HARDWARE
        }

    data class Case(
        val name: String,
        val jsonPath: Path,
        val pemPath: Path,
        val model: AttestationJson
    )

    val root = readResourceDir("android-keyattestation-testdata")
    val jsonFiles = Files.walk(root)
        .filter { it.toString().endsWith(".json") }
        .toList()
        .sorted()

    // build cases (json + matching pem with same basename)
    val cases: List<Case> = jsonFiles.map { jsonPath ->
        val rel = root.relativize(jsonPath)                 // <-- relativ zum Root
        val relStr = rel.toString().replace('\\', '/')      // Windows -> Slashes
        val pemPath = jsonPath.parent.resolve(rel.fileName.toString().substringBeforeLast(".json") + ".pem")
        check(Files.exists(pemPath)) { "PEM chain missing for $jsonPath" }

        val json = Json { ignoreUnknownKeys = true }
            .decodeFromString<AttestationJson>(readString(jsonPath))

        Case(name = relStr, jsonPath = jsonPath, pemPath = pemPath, model = json)
    }

    "Android Key Attestation corpus (${cases.size} cases)" - {
        withData(cases) { c ->
            println("run test: " + c.name)
            // 1) cert chain
            val chain = loadPemChain(readString(c.pemPath))
            chain.shouldNotBeNull()
            chain.isNotEmpty() shouldBe true

            // sanity: our DER roundtrip
            chain.forEach { cert ->
                val der = cert.encoded
                val parsed = SigNumX509.decodeFromDer(der)
                parsed.encodeToDer() shouldBe der
            }

            // 2) extract appId digest + pkg
            val pkgName = c.model.softwareEnforced?.attestationApplicationId?.packages?.firstOrNull()?.name
                ?: "unknown.package" // fallback
            val expectedDigest: ByteArray = c.model.softwareEnforced
                ?.attestationApplicationId?.signatures?.firstOrNull()
                ?.let { Base64.decode(it) }
                ?: ByteArray(0) // fallback (won't match anyway)

            // 3) challenge + time
            val challenge = Base64.decode(c.model.attestationChallenge)
            val creationMillis = c.model.softwareEnforced?.creationDateTime?.toLongOrNull()
            val iso = creationMillis?.let {Instant.ofEpochMilli(it) }
            val verificationDate: Date = creationMillis?.let { Date(it) } ?: Date()

            // 4) level + expected outcome

            // TODO Manfred 02.09.2025: not sure how to set level correctly
            val level =
                c.model.keyMintSecurityLevel // gives "CertificateInvalidException: No matching root certificate"
            val aLevel =
                c.model.attestationSecurityLevel // gives "AttestationValueException: Keymaster security level not software"

            val verifiedBootState = c.model.hardwareEnforced?.rootOfTrust?.verifiedBootState?.uppercase()
            val deviceLocked = c.model.hardwareEnforced?.rootOfTrust?.deviceLocked

            println("${c.name}: verifiedBootState=$verifiedBootState level=${level} iso=$iso")

            // 5) build checker (wie in BasicParsingTests.kt)
            val service = attestationService(
                attestationLevel = mapSecurityLevel(level, aLevel),
                androidPackageName = pkgName,
                androidAppSignatureDigest = listOf(expectedDigest),
                // optional: requireStrongBox = (c.model.attestationSecurityLevel?.uppercase() == "STRONG_BOX"),
                attestationStatementValiditiy = kotlin.time.Duration.parse("5m")
            )

            if (verifiedBootState == "UNVERIFIED") {
                val ex = shouldThrow<AttestationValueException> {
                    service.verifyAttestation(chain, verificationDate, challenge)
                }
                if (ex.message == "Bootloader not locked") {
                    deviceLocked shouldBe false
                } else {
                    throw TestAbortedException("UNVERIFIED : unknown case")
                }
            } else {
                service.verifyAttestation(chain, verificationDate, challenge)
            }
        }
    }
})
