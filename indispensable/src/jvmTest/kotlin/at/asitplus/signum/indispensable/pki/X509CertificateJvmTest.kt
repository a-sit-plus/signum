package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.internals.ensureSize
import at.asitplus.signum.indispensable.asn1.encoding.parse
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.coroutines.launch
import kotlinx.datetime.toKotlinInstant
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.operator.ContentSigner
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*
import kotlin.math.absoluteValue
import kotlin.random.Random
import kotlin.time.Duration.Companion.days

class X509CertificateJvmTest : FreeSpec({

    lateinit var ecCurve: ECCurve
    lateinit var keyPair: KeyPair

    beforeTest {
        ecCurve = ECCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
    }

    "Certificates match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = ecPublicKey.toCryptoPublicKey().getOrThrow()

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val issuer = X500Name("CN=$commonName")
        val builder = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ serialNumber,
            /* notBefore = */ notBeforeDate,
            /* notAfter = */ notAfterDate,
            /* subject = */ issuer,
            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val signatureAlgorithm = X509SignatureAlgorithm.ES256
        val contentSigner: ContentSigner = signatureAlgorithm.getContentSigner(keyPair.private)
        val certificateHolder = builder.build(contentSigner)

        // create certificate with our structure
        val tbsCertificate = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = Asn1Time(notBeforeDate.toInstant().toKotlinInstant()),
            validUntil = Asn1Time(notAfterDate.toInstant().toKotlinInstant()),
            signatureAlgorithm = signatureAlgorithm,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey
        )
        val signed = signatureAlgorithm.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCertificate.encodeToTlv().derEncoded)
        }.sign()
        val test = CryptoSignature.decodeFromDer(signed)
        val x509Certificate = X509Certificate(tbsCertificate, signatureAlgorithm, test)

        val kotlinEncoded = x509Certificate.encodeToDer()
        val jvmEncoded = certificateHolder.encoded
        println(
            "Certificates will never entirely match because of randomness in ECDSA signature" +
                    "\nKotlinEncoded\n" +
                    kotlinEncoded.encodeToString(Base16()) +
                    "\nJvmEncoded\n" +
                    jvmEncoded.encodeToString(Base16())
        )
        kotlinEncoded.drop(7).take(228) shouldBe jvmEncoded.drop(7).take(228)

        val parsedFromKotlinCertificate =
            CertificateFactory.getInstance("X.509").generateCertificate(kotlinEncoded.inputStream())
        parsedFromKotlinCertificate.verify(keyPair.public)
    }

    "Certificates Conversions" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = ecPublicKey.toCryptoPublicKey().getOrThrow()

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = X509SignatureAlgorithm.ES256


        // create certificate with our structure
        val tbsCertificate = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = Asn1Time(notBeforeDate.toInstant().toKotlinInstant()),
            validUntil = Asn1Time(notAfterDate.toInstant().toKotlinInstant()),
            signatureAlgorithm = signatureAlgorithm,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey
        )
        val signed = signatureAlgorithm.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCertificate.encodeToTlv().derEncoded)
        }.sign()
        val test = CryptoSignature.decodeFromDer(signed)
        val x509Certificate = X509Certificate(tbsCertificate, signatureAlgorithm, test)

        repeat(500) {
            launch {
                x509Certificate.toJcaCertificate().getOrThrow().toKmpCertificate().getOrThrow()
                    .encodeToDer() shouldBe x509Certificate.encodeToDer()
            }
        }
    }

    "Certificate can be parsed" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLength.bytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLength.bytes)

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val issuer = X500Name("CN=$commonName")
        val builder = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ serialNumber,
            /* notBefore = */ notBeforeDate,
            /* notAfter = */ notAfterDate,
            /* subject = */ issuer,
            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        )
        val signatureAlgorithm = X509SignatureAlgorithm.ES256
        val contentSigner: ContentSigner = signatureAlgorithm.getContentSigner(keyPair.private)
        val certificateHolder = builder.build(contentSigner)

        val x509Certificate =
            X509Certificate.decodeFromTlv(Asn1Element.parse(certificateHolder.encoded) as Asn1Sequence)
        x509Certificate.shouldNotBeNull()

        //x509Certificate.encodeToDer() shouldBe certificateHolder.encoded
        x509Certificate.signatureAlgorithm shouldBe signatureAlgorithm
        x509Certificate.tbsCertificate.version shouldBe 2
        (x509Certificate.tbsCertificate.issuerName.first().attrsAndValues.first().value as Asn1Primitive).content shouldBe commonName.encodeToByteArray()
        (x509Certificate.tbsCertificate.subjectName.first().attrsAndValues.first().value as Asn1Primitive).content shouldBe commonName.encodeToByteArray()
        x509Certificate.tbsCertificate.serialNumber shouldBe serialNumber.toByteArray()
        x509Certificate.tbsCertificate.signatureAlgorithm shouldBe signatureAlgorithm
        x509Certificate.tbsCertificate.validFrom.instant shouldBe notBeforeDate.toInstant()
            .truncatedTo(ChronoUnit.SECONDS)
            .toKotlinInstant()
        x509Certificate.tbsCertificate.validUntil.instant shouldBe notAfterDate.toInstant()
            .truncatedTo(ChronoUnit.SECONDS)
            .toKotlinInstant()
        val parsedPublicKey = x509Certificate.tbsCertificate.publicKey
        parsedPublicKey.shouldBeInstanceOf<CryptoPublicKey.EC>()
        parsedPublicKey.xBytes shouldBe keyX
        parsedPublicKey.yBytes shouldBe keyY
    }



    "Equals & hashCode" {

        /*
            TbsCertificate
        */
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = ecPublicKey.toCryptoPublicKey().getOrThrow()

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val validFromDate = Asn1Time(notBeforeDate.toInstant().toKotlinInstant())
        val validUntilDate = Asn1Time(notAfterDate.toInstant().toKotlinInstant())
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"

        val signatureAlgorithm256 = X509SignatureAlgorithm.ES256
        val signatureAlgorithm512 = X509SignatureAlgorithm.ES512

        // create certificate with our structure
        val tbsCertificate1 = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = validFromDate,
            validUntil = validUntilDate,
            signatureAlgorithm = signatureAlgorithm256,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey
        )
        val tbsCertificate2 = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = validFromDate,
            validUntil = validUntilDate,
            signatureAlgorithm = signatureAlgorithm256,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey
        )
        val tbsCertificate3 = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = validFromDate,
            validUntil = validUntilDate,
            signatureAlgorithm = signatureAlgorithm512,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey
        )
        val tbsCertificate4 = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = validFromDate,
            validUntil = validUntilDate,
            signatureAlgorithm = signatureAlgorithm256,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("DefaultCryptoService1")))),
            publicKey = cryptoPublicKey
        )
        val tbsCertificate5 = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = Asn1Time(Date.from(Instant.now().plusSeconds(1)).toInstant().toKotlinInstant()),
            validUntil = Asn1Time(
                Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds)).toInstant().toKotlinInstant()
            ),
            signatureAlgorithm = signatureAlgorithm256,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey
        )

        tbsCertificate1 shouldBe tbsCertificate1
        tbsCertificate1 shouldBe tbsCertificate2
        tbsCertificate1 shouldNotBe tbsCertificate3
        tbsCertificate1 shouldNotBe tbsCertificate4
        tbsCertificate1 shouldNotBe tbsCertificate5

        tbsCertificate1.hashCode() shouldBe tbsCertificate1.hashCode()
        tbsCertificate1.hashCode() shouldBe tbsCertificate2.hashCode()
        tbsCertificate1.hashCode() shouldNotBe tbsCertificate3.hashCode()
        tbsCertificate1.hashCode() shouldNotBe tbsCertificate4.hashCode()
        tbsCertificate1.hashCode() shouldNotBe tbsCertificate5.hashCode()

        /*
            X509Certificate
        */

        val signed1 = signatureAlgorithm256.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCertificate1.encodeToTlv().derEncoded)
        }.sign()
        val signed2 = signatureAlgorithm256.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCertificate2.encodeToTlv().derEncoded)
        }.sign()
        val signed3 = signatureAlgorithm512.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCertificate3.encodeToTlv().derEncoded)
        }.sign()
        val signature1 =
            (CryptoSignature.decodeFromDer(signed1) as CryptoSignature.EC.IndefiniteLength).withCurve(ECCurve.SECP_256_R_1)
        val signature2 =
            (CryptoSignature.decodeFromDer(signed2) as CryptoSignature.EC.IndefiniteLength).withCurve(ECCurve.SECP_256_R_1)
        val signature3 =
            (CryptoSignature.decodeFromDer(signed3) as CryptoSignature.EC.IndefiniteLength).withCurve(ECCurve.SECP_521_R_1)
        val x509Certificate1 = X509Certificate(tbsCertificate1, signatureAlgorithm256, signature1)
        val x509Certificate2 = X509Certificate(tbsCertificate2, signatureAlgorithm256, signature2)
        val x509Certificate3 = X509Certificate(tbsCertificate3, signatureAlgorithm512, signature3)
        val x509Certificate4 = X509Certificate(tbsCertificate4, signatureAlgorithm256, signature1)
        val x509Certificate5 = X509Certificate(tbsCertificate5, signatureAlgorithm256, signature1)

        x509Certificate1 shouldBe x509Certificate1
        x509Certificate1 shouldNotBe x509Certificate2
        x509Certificate1 shouldNotBe x509Certificate3
        x509Certificate1 shouldNotBe x509Certificate4
        x509Certificate1 shouldNotBe x509Certificate5

        x509Certificate1.hashCode() shouldBe x509Certificate1.hashCode()
        x509Certificate1.hashCode() shouldNotBe x509Certificate2.hashCode()
        x509Certificate1.hashCode() shouldNotBe x509Certificate3.hashCode()
        x509Certificate1.hashCode() shouldNotBe x509Certificate4.hashCode()
        x509Certificate1.hashCode() shouldNotBe x509Certificate5.hashCode()

        /*
            X509CertificateExtension
        */

        val keyUsage = KeyUsage(KeyUsage.digitalSignature)
        val extendedKeyUsage = ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)

        val ext1 = X509CertificateExtension(
            KnownOIDs.keyUsage,
            value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(keyUsage.encoded))),
            critical = true
        )
        val ext2 = X509CertificateExtension(
            KnownOIDs.keyUsage,
            value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(keyUsage.encoded))),
            critical = true
        )
        val ext3 = X509CertificateExtension(
            KnownOIDs.extKeyUsage,
            value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(extendedKeyUsage.encoded))),
            critical = true
        )
        val ext4 = X509CertificateExtension(
            KnownOIDs.keyUsage,
            value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(extendedKeyUsage.encoded))),
            critical = true
        )
        val ext5 = X509CertificateExtension(
            KnownOIDs.keyUsage,
            value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(keyUsage.encoded))),
            critical = false
        )

        ext1 shouldBe ext1
        ext1 shouldBe ext2
        ext1 shouldNotBe ext3
        ext1 shouldNotBe ext4
        ext1 shouldNotBe ext5

        ext1.hashCode() shouldBe ext1.hashCode()
        ext1.hashCode() shouldBe ext2.hashCode()
        ext1.hashCode() shouldNotBe ext3.hashCode()
        ext1.hashCode() shouldNotBe ext4.hashCode()
        ext1.hashCode() shouldNotBe ext5.hashCode()

        val tbsCertificate6 = TbsCertificate(
            version = 2,
            serialNumber = serialNumber.toByteArray(),
            issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            validFrom = validFromDate,
            validUntil = validUntilDate,
            signatureAlgorithm = signatureAlgorithm256,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey,
            extensions = listOf(ext1)
        )

        tbsCertificate6 shouldBe tbsCertificate6
        tbsCertificate1 shouldNotBe tbsCertificate6

        tbsCertificate6.hashCode() shouldBe tbsCertificate6.hashCode()
        tbsCertificate1.hashCode() shouldNotBe tbsCertificate6.hashCode()

    }

})