@file:OptIn(ExperimentalEncodingApi::class)

package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.attestation.android.exceptions.AttestationValueException
import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.signum.indispensable.pki.X509Certificate as SigNumX509
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.bouncycastle.util.encoders.Base64
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
import java.util.Date
import kotlin.io.encoding.ExperimentalEncodingApi


@OptIn(ExperimentalStdlibApi::class)
class KeyAttestationCorpusTests : FreeSpec({

    @Serializable
    data class AppPkg(
        val name: String,
        val version: String? = null
    )

    @Serializable
    data class RootOfTrust(
        val verifiedBootState: String? = null // "VERIFIED" | "UNVERIFIED" | "SELF_SIGNED" ...
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
        val creationDateTime: String? = null, // millis as string
        val attestationApplicationId: AttestationApplicationId? = null
    )

    @Serializable
    data class AttestationJson(
        val attestationChallenge: String,
        val attestationSecurityLevel: String? = null, // "TEE" | "STRONG_BOX" | "SOFTWARE"
        val softwareEnforced: SoftwareEnforced? = null,
        val hardwareEnforced: HardwareEnforced? = null
    )

    fun cleanHex(s: String) = s.replace("\\s+".toRegex(), "")

    fun isoFromMillis(millis: Long): String =
        DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(millis).atOffset(ZoneOffset.UTC))

    fun readResourceDir(dir: String): Path {
        val url = checkNotNull(javaClass.classLoader.getResource(dir)) {
            "Resource directory not found: $dir"
        }
        return Paths.get(url.toURI())
    }

    fun readString(p: Path): String = Files.readString(p, StandardCharsets.UTF_8)

    fun loadPemChain(pemText: String): List<X509Certificate> {
        val cf = CertificateFactory.getInstance("X.509")
        val re = Regex(
            "-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----",
            setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.MULTILINE)
        )
        return re.findAll(pemText).map { m ->
            val body = m.groupValues[1].replace("\\s+".toRegex(), "")
            val der = Base64.decode(body)
            cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }.toList()
    }

    /*
    fun AttestationData.Level.Companion.fromSecurityLevel(s: String?): AttestationData.Level =
        when (s?.uppercase()) {
            "SOFTWARE" -> AttestationData.Level.SOFTWARE
            "TEE", "STRONG_BOX" -> AttestationData.Level.HARDWARE
            else -> AttestationData.Level.HARDWARE
        }
     */

    fun mapSecurityLevel(s: String?): AttestationData.Level =
        when (s?.uppercase()) {
            "SOFTWARE" -> AttestationData.Level.SOFTWARE
            "TEE", "STRONG_BOX" -> AttestationData.Level.HARDWARE
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
        val base = jsonPath.fileName.toString().substringBeforeLast(".json")
        val pemPath = jsonPath.parent.resolve("$base.pem")
        check(Files.exists(pemPath)) { "PEM chain missing for $jsonPath" }
        val json = Json { ignoreUnknownKeys = true }
            .decodeFromString<AttestationJson>(readString(jsonPath))
        Case(name = "${jsonPath.parent.fileName}/$base", jsonPath, pemPath, json)
    }

    "Android Key Attestation corpus (${cases.size} cases)" - {
        withData(cases) { c ->
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
            val iso = creationMillis?.let { isoFromMillis(it) } ?: Instant.EPOCH.toString()
            val verificationDate: Date = creationMillis?.let { Date(it) } ?: Date()

            // 4) level + expected outcome
            //val level = AttestationData.Level.fromSecurityLevel(c.model.attestationSecurityLevel)
            val level = mapSecurityLevel(c.model.attestationSecurityLevel)
            val verifiedBootState = c.model.hardwareEnforced?.rootOfTrust?.verifiedBootState?.uppercase()
            val shouldFail = verifiedBootState == "UNVERIFIED";

            println("should Fail"+shouldFail);

            // 5) build checker (wie in BasicParsingTests.kt)
            val service = attestationService(
                attestationLevel = level,
                androidPackageName = pkgName,
                androidAppSignatureDigest = listOf(expectedDigest),
                // optional: requireStrongBox = (c.model.attestationSecurityLevel?.uppercase() == "STRONG_BOX"),
                attestationStatementValiditiy = kotlin.time.Duration.parse("5m")
            )

            if (shouldFail) {
                shouldThrow<AttestationValueException> {
                    service.verifyAttestation(chain, verificationDate, challenge)
                }.message shouldBe "Bootloader not locked"
            } else {
                service.verifyAttestation(chain, verificationDate, challenge)
            }

            // 7) optional Log
            println("${c.name}: verifiedBootState=$verifiedBootState level=${c.model.attestationSecurityLevel} iso=$iso shouldFail=$shouldFail")
        }
    }
})
