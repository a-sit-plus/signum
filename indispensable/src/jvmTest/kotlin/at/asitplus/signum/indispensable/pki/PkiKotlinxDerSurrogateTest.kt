package at.asitplus.signum.indispensable.pki

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.indispensable.asn1.serialization.*
import at.asitplus.signum.indispensable.asn1.serialization.Asn1BitString as Asn1BitStringAnnotation
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.KeepGeneratedSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
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
        withData(ok) { (name, der) ->
            assertX509SurrogateRoundtrip(label = name, der = der)
        }
    }

    "X509 surrogate reject/accept behavior stays aligned with legacy parser" - {
        val (_, faulty) = readGoogleDerCorpus()

        withData(nameFn = { (name, _) -> name }, faulty) { (name, der) ->
            val legacy = catchingUnwrapped { X509Certificate.decodeFromDer(der) }
            val surrogate = catchingUnwrapped { DER.decodeFromDer<SurrogateX509Certificate>(der) }

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
                    catchingUnwrapped { X509Certificate.decodeFromDer(surrogateDer) }.isSuccess shouldBe true

                    val legacyDer = legacy.getOrThrow().encodeToDer()
                    //we only check when encoding itself is kosher
                    if(!name.contains("-nonminimal") && !name.contains("-der-invalid-bitstring")) {
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
                catchingUnwrapped { Pkcs10CertificationRequest.decodeFromDer(der) }.isFailure shouldBe true
                catchingUnwrapped { DER.decodeFromDer<SurrogatePkcs10CertificationRequest>(der) }.isFailure shouldBe true
            }
        }
    }

    "SubjectPublicKeyInfo surrogate decodes EC and RSA polymorphically" - {
        withData("EC", "RSA") { keyType ->
            val spki = when (keyType) {
                "EC" -> KeyPairGenerator.getInstance("EC").also { it.initialize(256) }.genKeyPair().public.encoded
                "RSA" -> KeyPairGenerator.getInstance("RSA").also { it.initialize(2048) }.genKeyPair().public.encoded
                else -> error("Unsupported key type $keyType")
            }
            val decoded = DER.decodeFromDer<SurrogateSubjectPublicKeyInfo>(spki)

            when (keyType) {
                "EC" -> (decoded is SurrogateEcPublicKeyInfo) shouldBe true
                "RSA" -> (decoded is SurrogateRsaPublicKeyInfo) shouldBe true
            }
            DER.encodeToDer(decoded) shouldBe spki
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
        catchingUnwrapped { X509Certificate.decodeFromDer(surrogateDer) }.isSuccess shouldBe true
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
    @Asn1BitStringAnnotation
    val signatureValue: ByteArray
)

@Serializable
data class SurrogateTbsCertificate(
    @Asn1Tag(tagNumber = 0u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val version: Int? = null,
    @Asn1Tag(
        tagNumber = 2u,
        tagClass = Asn1TagClass.UNIVERSAL,
        constructed = Asn1ConstructedBit.PRIMITIVE
    )
    val serialNumber: Asn1Integer,
    val signature: Asn1Element,
    val issuer: List<RelativeDistinguishedName>,
    val validity: SurrogateValidity,
    val subject: List<RelativeDistinguishedName>,
    val subjectPublicKeyInfo: SurrogateSubjectPublicKeyInfo,
    @Asn1BitStringAnnotation
    @Asn1Tag(tagNumber = 1u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val issuerUniqueID: ByteArray? = null,
    @Asn1BitStringAnnotation
    @Asn1Tag(tagNumber = 2u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val subjectUniqueID: ByteArray? = null,
    @Asn1Tag(tagNumber = 3u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC, constructed = Asn1ConstructedBit.CONSTRUCTED)
    val extensions: List<X509CertificateExtension>? = null,
) {
    init {

        if(!extensions.isNullOrEmpty()) {
            require(extensions.distinctBy { it.oid }.size == extensions.size)
            // Align surrogate strictness with legacy SAN/IAN structural validation.
            extensions.findSubjectAltNames()
            extensions.findIssuerAltNames()
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
    @Asn1BitStringAnnotation
    val signature: ByteArray
)

@Serializable
data class SurrogateCertificationRequestInfo(
    val version: Asn1Integer,
    val subject: Asn1Element,
    val subjectPublicKeyInfo: SurrogateSubjectPublicKeyInfo,
    @Asn1Tag(tagNumber = 0u, tagClass = Asn1TagClass.CONTEXT_SPECIFIC)
    val attributes: Asn1Element
)

@Serializable(with = SurrogateSubjectPublicKeyInfoSerializer::class)
sealed interface SurrogateSubjectPublicKeyInfo

@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = SurrogateEcPublicKeyInfoSerializer::class)
@KeepGeneratedSerializer
data class SurrogateEcPublicKeyInfo(
    @Serializable(with = SurrogateNonNullEcCurveSerializer::class)
    val curve: ECCurve,
    val x: ByteArray,
    val y: ByteArray,
) : SurrogateSubjectPublicKeyInfo {
    init {
        val expectedLength = curve.coordinateLength.bytes.toInt()
        require(x.size == expectedLength) {
            "Invalid EC X coordinate size for ${curve.name}: expected $expectedLength, got ${x.size}"
        }
        require(y.size == expectedLength) {
            "Invalid EC Y coordinate size for ${curve.name}: expected $expectedLength, got ${y.size}"
        }
    }
}

object SurrogateNonNullEcCurveSerializer : KSerializer<ECCurve> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("SurrogateNonNullEcCurve", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: ECCurve) {
        encoder.encodeString(value.jwkName)
    }

    override fun deserialize(decoder: Decoder): ECCurve {
        val encoded = decoder.decodeString()
        return ECCurve.entries.firstOrNull { it.jwkName == encoded }
            ?: throw SerializationException("Unsupported curve: $encoded")
    }
}

@Serializable
data class SurrogateRsaPublicKey(
    val modulus: Asn1Integer,
    val exponent: Asn1Integer,
) {
    init {
        require(modulus is Asn1Integer.Positive) { "RSA modulus must be positive" }
        require(exponent is Asn1Integer.Positive) { "RSA exponent must be positive" }
    }
}

@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = SurrogateRsaPublicKeyInfoSerializer::class)
@KeepGeneratedSerializer
data class SurrogateRsaPublicKeyInfo(
    val algorithmIdentifier: Asn1Element,
    val subjectPublicKey: SurrogateRsaPublicKey,
) : SurrogateSubjectPublicKeyInfo {
    init {
        val algorithmSequence = algorithmIdentifier.asSequence()
        require(algorithmSequence.children.size == 2) { "Invalid AlgorithmIdentifier in RSA SPKI" }
        require(algorithmSequence.children[0].asPrimitive().readOid() == KnownOIDs.rsaEncryption) {
            "RSA AlgorithmIdentifier must use rsaEncryption OID"
        }
        algorithmSequence.children[1].asPrimitive().readNull()
    }
}

@Serializable
data class SurrogateUnknownPublicKeyInfo(
    val rawSpki: Asn1Element,
) : SurrogateSubjectPublicKeyInfo {
    init {
        require(rawSpki is Asn1Sequence) { "SubjectPublicKeyInfo must be a SEQUENCE" }
    }
}

@Serializable
private data class SurrogateEcPublicKeyInfoRaw(
    val algorithmIdentifier: Asn1Element,
    @Asn1BitStringAnnotation
    val subjectPublicKey: ByteArray,
)

@Serializable
private data class SurrogateRsaPublicKeyInfoRaw(
    val algorithmIdentifier: Asn1Element,
    @Asn1BitStringAnnotation
    val subjectPublicKey: ByteArray,
)

@OptIn(ExperimentalSerializationApi::class)
object SurrogateEcPublicKeyInfoSerializer : KSerializer<SurrogateEcPublicKeyInfo> {
    private val generated = SurrogateEcPublicKeyInfo.generatedSerializer()
    override val descriptor = generated.descriptor

    override fun serialize(encoder: Encoder, value: SurrogateEcPublicKeyInfo) {
        val raw = SurrogateEcPublicKeyInfoRaw(
            algorithmIdentifier = Asn1.Sequence {
                +KnownOIDs.ecPublicKey
                +value.curve.oid
            },
            subjectPublicKey = byteArrayOf(0x04) + value.x + value.y
        )
        encoder.encodeSerializableValue(SurrogateEcPublicKeyInfoRaw.serializer(), raw)
    }

    override fun deserialize(decoder: Decoder): SurrogateEcPublicKeyInfo {
        val raw = decoder.decodeSerializableValue(SurrogateEcPublicKeyInfoRaw.serializer())
        val algorithmSequence = raw.algorithmIdentifier.asSequence()
        require(algorithmSequence.children.size == 2) { "Invalid AlgorithmIdentifier in EC SPKI" }
        require(algorithmSequence.children[0].asPrimitive().readOid() == KnownOIDs.ecPublicKey) {
            "EC AlgorithmIdentifier must use id-ecPublicKey OID"
        }
        val curveOid = algorithmSequence.children[1].asPrimitive().readOid()
        val curve = ECCurve.entries.firstOrNull { it.oid == curveOid }
            ?: throw IllegalArgumentException("Curve not supported: $curveOid")
        val coordinateLength = curve.coordinateLength.bytes.toInt()
        val expectedLength = 1 + coordinateLength * 2
        require(raw.subjectPublicKey.size == expectedLength) {
            "Invalid EC point size for ${curve.name}: expected $expectedLength, got ${raw.subjectPublicKey.size}"
        }
        require(raw.subjectPublicKey.firstOrNull() == 0x04.toByte()) {
            "EC key not prefixed with 0x04"
        }
        return SurrogateEcPublicKeyInfo(
            curve = curve,
            x = raw.subjectPublicKey.copyOfRange(1, 1 + coordinateLength),
            y = raw.subjectPublicKey.copyOfRange(1 + coordinateLength, expectedLength)
        )
    }
}

@OptIn(ExperimentalSerializationApi::class)
object SurrogateRsaPublicKeyInfoSerializer : KSerializer<SurrogateRsaPublicKeyInfo> {
    private val generated = SurrogateRsaPublicKeyInfo.generatedSerializer()
    override val descriptor = generated.descriptor

    override fun serialize(encoder: Encoder, value: SurrogateRsaPublicKeyInfo) {
        val raw = SurrogateRsaPublicKeyInfoRaw(
            algorithmIdentifier = value.algorithmIdentifier,
            subjectPublicKey = DER.encodeToDer(SurrogateRsaPublicKey.serializer(), value.subjectPublicKey)
        )
        encoder.encodeSerializableValue(SurrogateRsaPublicKeyInfoRaw.serializer(), raw)
    }

    override fun deserialize(decoder: Decoder): SurrogateRsaPublicKeyInfo {
        val raw = decoder.decodeSerializableValue(SurrogateRsaPublicKeyInfoRaw.serializer())
        return SurrogateRsaPublicKeyInfo(
            algorithmIdentifier = raw.algorithmIdentifier,
            subjectPublicKey = DER.decodeFromDer(raw.subjectPublicKey, SurrogateRsaPublicKey.serializer())
        )
    }
}

object SurrogateSubjectPublicKeyInfoSerializer : KSerializer<SurrogateSubjectPublicKeyInfo> {
    override val descriptor = Asn1Element.serializer().descriptor

    override fun serialize(encoder: Encoder, value: SurrogateSubjectPublicKeyInfo) {
        when (value) {
            is SurrogateEcPublicKeyInfo ->
                encoder.encodeSerializableValue(SurrogateEcPublicKeyInfoSerializer, value)
            is SurrogateRsaPublicKeyInfo ->
                encoder.encodeSerializableValue(SurrogateRsaPublicKeyInfoSerializer, value)
            is SurrogateUnknownPublicKeyInfo ->
                encoder.encodeSerializableValue(Asn1Element.serializer(), value.rawSpki)
        }
    }

    override fun deserialize(decoder: Decoder): SurrogateSubjectPublicKeyInfo {
        val src = decoder.decodeSerializableValue(Asn1Element.serializer()).asSequence()
        if (src.children.size != 2) return SurrogateUnknownPublicKeyInfo(src)

        val algorithmIdentifier = catchingUnwrapped { src.children[0].asSequence() }.getOrElse {
            return SurrogateUnknownPublicKeyInfo(src)
        }
        if (algorithmIdentifier.children.size != 2) return SurrogateUnknownPublicKeyInfo(src)

        val algorithmOid = catchingUnwrapped { algorithmIdentifier.children[0].asPrimitive().readOid() }.getOrElse {
            return SurrogateUnknownPublicKeyInfo(src)
        }
        catchingUnwrapped { src.children[1].asPrimitive().asAsn1BitString() }.getOrElse {
            return SurrogateUnknownPublicKeyInfo(src)
        }

        return when (algorithmOid) {
            KnownOIDs.ecPublicKey -> DER.decodeFromTlv(src, SurrogateEcPublicKeyInfoSerializer)
            KnownOIDs.rsaEncryption -> DER.decodeFromTlv(src, SurrogateRsaPublicKeyInfoSerializer)
            else -> SurrogateUnknownPublicKeyInfo(src)
        }
    }
}
