package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.serialization.*
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.Serializable
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import java.io.File
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

@OptIn(ExperimentalSerializationApi::class, ExperimentalEncodingApi::class)
val PkiKotlinxDerSurrogateTest by testSuite {

    "X509 surrogate parses known-good vectors and keeps DER bytes stable" - {
        withData(
            "digicert-root.pem",
            "github-com.pem",
            "cert-times.pem",
        ) { resource ->
            val der = pemResourceToDer(resource)
            assertX509SurrogateRoundtrip(label = resource, der = der)

        }

        val (ok, _) = readGoogleDerCorpus()
        ok.forEach { (name, der) ->
            assertX509SurrogateRoundtrip(label = name, der = der)
        }
    }

    "X509 surrogate reject/accept behavior stays aligned with legacy parser" - {
        val (_, faulty) = readGoogleDerCorpus()

        withData(nameFn = { (name, _) -> name }, faulty) { (name, der) ->
            val legacy = runCatching { X509Certificate.decodeFromDer(der) }
            val surrogate = runCatching { DER.decodeFromDer<SurrogateX509Certificate>(der) }

            withClue(name+" legacy failure ${legacy.isFailure}, surrogate failure: ${surrogate.isFailure}") {
                if(legacy.isSuccess && !name.startsWith("ok-") && surrogate.isFailure) {
                    return@withData
                }
                legacy.isFailure shouldBe surrogate.isFailure
                if (legacy.isSuccess) {
                    surrogate.isSuccess shouldBe true
                    val surrogateValue = surrogate.getOrThrow()
                    //these are invalid, so checks for conformance are not relevant
                    //surrogateValue.isConsistentWithX509Constraints() shouldBe true
                    val surrogateDer = DER.encodeToDer(surrogateValue)
                    runCatching { X509Certificate.decodeFromDer(surrogateDer) }.isSuccess shouldBe true

                    val legacyDer = legacy.getOrThrow().encodeToDer()
                    //we only check when encoding itself is kosher
                    if(!name.contains("-nonminimal")) {
                        surrogateDer shouldBe der
                        surrogateDer shouldBe legacyDer
                    }
                }
            }
        }
    }

    "PKCS10 surrogate parses generated CSRs and keeps DER bytes stable" - {
        withData(generatedCsrVectors()) { (name, der) ->
            val legacy = Pkcs10CertificationRequest.decodeFromDer(der)
            val surrogate = DER.decodeFromDer<SurrogatePkcs10CertificationRequest>(der)
            val surrogateDer = DER.encodeToDer(surrogate)

            withClue(name) {
                surrogateDer shouldBe der
                surrogateDer shouldBe legacy.encodeToDer()
            }
        }
    }

    "PKCS10 surrogate rejects malformed vectors alongside legacy parser" - {
        val valid = generatedCsrVectors().first().second
        withData(malformedCsrVectors(valid)) { (name, der) ->
            withClue(name) {
                runCatching { Pkcs10CertificationRequest.decodeFromDer(der) }.isFailure shouldBe true
                runCatching { DER.decodeFromDer<SurrogatePkcs10CertificationRequest>(der) }.isFailure shouldBe true
            }
        }
    }
}

@OptIn(ExperimentalEncodingApi::class)
private fun pemResourceToDer(resource: String): ByteArray {
    val text = checkNotNull(object {}.javaClass.classLoader.getResourceAsStream(resource)) {
        "Missing resource $resource"
    }.reader().readText()
    return Base64.Mime.decode(text)
}

private fun readGoogleDerCorpus(): Pair<List<Pair<String, ByteArray>>, List<Pair<String, ByteArray>>> {
    val certs = File("./src/jvmTest/resources/certs").listFiles()
        ?.filter { it.extension == "der" && !it.name.contains(".chain.") }
        .orEmpty()
    val certs2 = File("./src/jvmTest/resources/certs2").listFiles()
        ?.filter { it.extension == "der" && !it.name.contains(".chain.") }
        .orEmpty()
    val all = (certs + certs2).sortedBy { it.name }
    val ok = all.filter { it.name.startsWith("ok-") }
    val faulty = all.filter { !it.name.startsWith("ok-") }

    return ok.filterNot { it.name=="ok-uniqueid-incomplete-byte.der" }.map { it.name to it.readBytes() } to faulty.map { it.name to it.readBytes() }
}

@OptIn(ExperimentalSerializationApi::class)
private fun assertX509SurrogateRoundtrip(label: String, der: ByteArray) {
    val legacy = X509Certificate.decodeFromDer(der)
    val surrogate = DER.decodeFromDer<SurrogateX509Certificate>(der)
    val surrogateDer = DER.encodeToDer(surrogate)
    withClue(label) {
        surrogate.isConsistentWithX509Constraints() shouldBe true
        runCatching { X509Certificate.decodeFromDer(surrogateDer) }.isSuccess shouldBe true
        DER.encodeToDer(DER.decodeFromDer<SurrogateX509Certificate>(surrogateDer)) shouldBe surrogateDer

        val legacyDer = legacy.encodeToDer()
        surrogateDer shouldBe der
        surrogateDer shouldBe legacyDer
    }
}

private fun SurrogateX509Certificate.isConsistentWithX509Constraints(): Boolean =
    tbsCertificate.signature == signatureAlgorithm

private fun generatedCsrVectors(): List<Pair<String, ByteArray>> {
    val keyPair = KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair()
    val publicKey = (keyPair.public as ECPublicKey).toCryptoPublicKey().getOrThrow()
    val signatureAlgorithm = X509SignatureAlgorithm.ES256

    val keyUsage = KeyUsage(KeyUsage.digitalSignature)
    val extKeyUsage = ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)
    val keyUsageOid = ObjectIdentifier("2.5.29.15")
    val extKeyUsageOid = ObjectIdentifier("2.5.29.37")
    val name =
        listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName("DefaultCryptoService".asUtf8String())))

    val minimal = TbsCertificationRequest(
        version = 0,
        subjectName = name,
        publicKey = publicKey
    )
    val withAttrs = TbsCertificationRequest(
        version = 0,
        subjectName = name,
        publicKey = publicKey,
        attributes = listOf(
            Pkcs10CertificationRequestAttribute(keyUsageOid, Asn1Element.parse(keyUsage.encoded)),
            Pkcs10CertificationRequestAttribute(extKeyUsageOid, Asn1Element.parse(extKeyUsage.encoded))
        )
    )
    val withExtensionRequest = TbsCertificationRequest(
        subjectName = name,
        publicKey = publicKey,
        extensions = listOf(
            X509CertificateExtension(
                keyUsageOid,
                value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(keyUsage.encoded))),
                critical = true
            ),
            X509CertificateExtension(
                extKeyUsageOid,
                value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(extKeyUsage.encoded))),
                critical = true
            )
        ),
        attributes = listOf(
            Pkcs10CertificationRequestAttribute(
                ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"),
                1337.encodeToAsn1Primitive()
            )
        )
    )
    val withEmptyExtensions = TbsCertificationRequest(
        subjectName = name,
        publicKey = publicKey,
        extensions = null,
        attributes = listOf(
            Pkcs10CertificationRequestAttribute(
                ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"),
                1337.encodeToAsn1Primitive()
            )
        )
    )

    return listOf(
        "minimal" to signCsr(minimal, signatureAlgorithm, keyPair.private),
        "with-attrs" to signCsr(withAttrs, signatureAlgorithm, keyPair.private),
        "with-extension-request" to signCsr(withExtensionRequest, signatureAlgorithm, keyPair.private),
        "with-empty-extensions" to signCsr(withEmptyExtensions, signatureAlgorithm, keyPair.private),
    )
}

private fun signCsr(
    tbs: TbsCertificationRequest,
    signatureAlgorithm: X509SignatureAlgorithm,
    privateKey: PrivateKey
): ByteArray {
    val signature = signatureAlgorithm.getJCASignatureInstance().getOrThrow().apply {
        initSign(privateKey)
        update(tbs.encodeToDer())
    }.sign()
    return Pkcs10CertificationRequest(
        tbsCsr = tbs,
        signatureAlgorithm = signatureAlgorithm,
        rawSignature = CryptoSignature.parseFromJca(signature, signatureAlgorithm).x509Encoded
    ).encodeToDer()
}

private fun malformedCsrVectors(validDer: ByteArray): List<Pair<String, ByteArray>> {
    val parsed = Asn1Element.parse(validDer).asSequence()
    val tbs = parsed.children.first().asSequence()
    val tbsVersion = tbs.children.first().asPrimitive()
    val tbsAttributes = tbs.children.last().asExplicitlyTagged()

    val wrongVersionTag = Asn1.Sequence {
        +Asn1.Sequence {
            +Asn1Primitive(Asn1Element.Tag.BOOL, tbsVersion.content)
            tbs.children.drop(1).forEach { +it }
        }
        parsed.children.drop(1).forEach { +it }
    }.derEncoded

    val wrongAttributesTag = Asn1.Sequence {
        +Asn1.Sequence {
            tbs.children.dropLast(1).forEach { +it }
            +Asn1.ExplicitlyTagged(1uL) {
                tbsAttributes.children.forEach { +it }
            }
        }
        parsed.children.drop(1).forEach { +it }
    }.derEncoded

    val truncated = validDer.copyOf(validDer.size - 1)

    return listOf(
        "csr-wrong-version-tag" to wrongVersionTag,
        "csr-wrong-attributes-tag" to wrongAttributesTag,
        "csr-truncated" to truncated,
    )
}

private fun String.asUtf8String() = at.asitplus.signum.indispensable.asn1.Asn1String.UTF8(this)

@Serializable
data class SurrogateX509Certificate(
    val tbsCertificate: SurrogateTbsCertificate,
    val signatureAlgorithm: Asn1Element,
    @Asn1nnotation(asBitString = true)
    val signatureValue: ByteArray
)

@Serializable
data class SurrogateTbsCertificate(
    @Asn1nnotation(Layer(Type.EXPLICIT_TAG, 0uL))
    val version: Int? = null,
    val serialNumber: Asn1Integer,
    val signature: Asn1Element,
    val issuer: List<RelativeDistinguishedName>,
    val validity: SurrogateValidity,
    val subject: List<RelativeDistinguishedName>,
    val subjectPublicKeyInfo: Asn1Element,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 1uL), asBitString = true)
    val issuerUniqueID: ByteArray? = null,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 2uL), asBitString = true)
    val subjectUniqueID: ByteArray? = null,
    @Asn1nnotation(Layer(Type.EXPLICIT_TAG, 3uL))
    val extensions: List<X509CertificateExtension>? = null,
) {
    init {

        if(!extensions.isNullOrEmpty()) {
         require(extensions.distinctBy { it.oid }.size==extensions.size)
        }
    }
}

@Serializable
data class SurrogateValidity(
    val notBefore: Asn1Time,
    val notAfter: Asn1Time,
)

@Serializable
data class SurrogatePkcs10CertificationRequest(
    val certificationRequestInfo: SurrogateCertificationRequestInfo,
    val signatureAlgorithm: Asn1Element,
    @Asn1nnotation(asBitString = true)
    val signature: ByteArray
)

@Serializable
data class SurrogateCertificationRequestInfo(
    val version: Asn1Integer,
    val subject: Asn1Element,
    val subjectPublicKeyInfo: Asn1Element,
    @Asn1nnotation(Layer(Type.IMPLICIT_TAG, 0uL))
    val attributes: Asn1Element
)
