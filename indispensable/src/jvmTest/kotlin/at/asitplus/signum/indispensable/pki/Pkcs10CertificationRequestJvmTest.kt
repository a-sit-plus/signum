package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.internals.ensureSize
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.TestConfig
import de.infix.testBalloon.framework.aroundEach
import de.infix.testBalloon.framework.testSuite
import io.kotest.assertions.withClue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey

internal fun X509SignatureAlgorithm.getContentSigner(key: PrivateKey) =
    getJCASignatureInstance().getOrThrow().algorithm.let {
        JcaContentSignerBuilder(it).build(key)
    }

@OptIn(ExperimentalStdlibApi::class)
val Pkcs10CertificationRequestJvmTest by testSuite {

    lateinit var ecCurve: ECCurve
    lateinit var keyPair: KeyPair
    lateinit var keyPair1: KeyPair

    testConfig = TestConfig.aroundEach {
        ecCurve = ECCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        keyPair1 = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        it()
    }


    "CSR match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = ecPublicKey.toCryptoPublicKey().getOrThrow()

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = X509SignatureAlgorithm.ES256


        val tbsCsr = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(
                RelativeDistinguishedName(
                    listOf(
                        AttributeTypeAndValue.CommonName(
                            Asn1String.UTF8(
                                commonName
                            )
                        )
                    )
                )
            ),
            publicKey = cryptoPublicKey
        )
        val signed = signatureAlgorithm.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToDer())
        }.sign()
        val csr = Pkcs10CertificationRequest(
            tbsCsr,
            signatureAlgorithm,
            CryptoSignature.parseFromJca(signed, signatureAlgorithm)
        )

        val kotlinEncoded = csr.encodeToDer()

        val contentSigner: ContentSigner =
            signatureAlgorithm.getContentSigner(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki).build(contentSigner)

        val jvmEncoded = bcCsr.encoded
        // CSR will never entirely match because of randomness in ECDSA signature
        //kotlinEncoded shouldBe jvmEncoded
        kotlinEncoded.drop(6).take(142) shouldBe jvmEncoded.drop(6).take(142)

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSR with attributes match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = ecPublicKey.toCryptoPublicKey().getOrThrow()

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = X509SignatureAlgorithm.ES256
        val contentSigner: ContentSigner = signatureAlgorithm.getContentSigner(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val keyUsage = KeyUsage(KeyUsage.digitalSignature)
        val extendedKeyUsage = ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)
        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki)
            .addAttribute(Extension.keyUsage, keyUsage)
            .addAttribute(Extension.extendedKeyUsage, extendedKeyUsage)
            .build(contentSigner)
        val tbsCsr = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(
                RelativeDistinguishedName(
                    listOf(
                        AttributeTypeAndValue.CommonName(
                            Asn1String.UTF8(
                                commonName
                            )
                        )
                    )
                )
            ),
            publicKey = cryptoPublicKey,
            attributes = listOf(
                Pkcs10CertificationRequestAttribute(KnownOIDs.keyUsage, Asn1Element.parse(keyUsage.encoded)),
                Pkcs10CertificationRequestAttribute(
                    KnownOIDs.extKeyUsage,
                    Asn1Element.parse(extendedKeyUsage.encoded)
                )
            )
        )
        val signed = signatureAlgorithm.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToTlv().derEncoded)
        }.sign()
        val csr = Pkcs10CertificationRequest(
            tbsCsr,
            signatureAlgorithm,
            CryptoSignature.parseFromJca(signed, signatureAlgorithm)
        )

        val kotlinEncoded = csr.encodeToTlv().derEncoded
        val jvmEncoded = bcCsr.encoded
        // CSR will never entirely match because of randomness in ECDSA signature
        //kotlinEncoded shouldBe jvmEncoded
        withClue(
            "kotlinEncoded: ${csr.encodeToTlv().toDerHexString()}, jvmEncoded: ${
                bcCsr.encoded.toHexString(
                    HexFormat.UpperCase
                )
            }"
        )
        { kotlinEncoded.drop(6).take(172) shouldBe jvmEncoded.drop(6).take(172) }

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSRs with extensionRequest match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = ecPublicKey.toCryptoPublicKey().getOrThrow()

        // create CSR with bouncycastle
        val commonName = "localhost"
        val signatureAlgorithm = X509SignatureAlgorithm.ES256
        val contentSigner: ContentSigner = signatureAlgorithm.getContentSigner(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val keyUsage = KeyUsage(KeyUsage.digitalSignature)
        val extendedKeyUsage = ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)

        val extGen = ExtensionsGenerator()

        extGen.addExtension(Extension.keyUsage, true, keyUsage)
        extGen.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage)

        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki)
            .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate())
            .addAttribute(ASN1ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"), ASN1Integer(1337L))
            .build(contentSigner)
        val tbsCsr = TbsCertificationRequest(
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey,
            extensions = listOf(
                X509CertificateExtension(
                    KnownOIDs.keyUsage,
                    value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(keyUsage.encoded))),
                    critical = true
                ),
                X509CertificateExtension(
                    KnownOIDs.extKeyUsage,
                    value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(extendedKeyUsage.encoded))),
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
        val signed = signatureAlgorithm.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToTlv().derEncoded)
        }.sign()
        val csr = Pkcs10CertificationRequest(
            tbsCsr,
            signatureAlgorithm,
            CryptoSignature.parseFromJca(signed, signatureAlgorithm)
        )

        val kotlinEncoded = csr.encodeToTlv().derEncoded
        val jvmEncoded = bcCsr.encoded
        // CSR will never entirely match because of randomness in ECDSA signature
        //kotlinEncoded shouldBe jvmEncoded
        kotlinEncoded.drop(6).take(172) shouldBe jvmEncoded.drop(6).take(172)

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSRs with empty extensions match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = ecPublicKey.toCryptoPublicKey().getOrThrow()

        // create CSR with bouncycastle
        val commonName = "localhost"
        val signatureAlgorithm = X509SignatureAlgorithm.ES256
        val contentSigner: ContentSigner = signatureAlgorithm.getContentSigner(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)


        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki)
            .addAttribute(ASN1ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"), ASN1Integer(1337L))
            .build(contentSigner)
        val tbsCsr = TbsCertificationRequest(
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey,
            extensions = null,
            attributes = listOf(
                Pkcs10CertificationRequestAttribute(
                    ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"),
                    1337.encodeToAsn1Primitive()
                )
            )
        )
        val signed = signatureAlgorithm.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToTlv().derEncoded)
        }.sign()
        val csr = Pkcs10CertificationRequest(
            tbsCsr,
            signatureAlgorithm,
            CryptoSignature.parseFromJca(signed, signatureAlgorithm)
        )

        val kotlinEncoded = csr.encodeToTlv().derEncoded
        val jvmEncoded = bcCsr.encoded

        // CSR will never entirely match because of randomness in ECDSA signature
        //kotlinEncoded shouldBe jvmEncoded
        kotlinEncoded.drop(6).take(152) shouldBe jvmEncoded.drop(6).take(152)

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSR can be parsed" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLength.bytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLength.bytes)

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = X509SignatureAlgorithm.ES256
        val contentSigner: ContentSigner = signatureAlgorithm.getContentSigner(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki).build(contentSigner)

        val csr = Pkcs10CertificationRequest.decodeFromTlv(Asn1Element.parse(bcCsr.encoded) as Asn1Sequence)
        csr.shouldNotBeNull()

        //x509Certificate.encodeToDer() shouldBe certificateHolder.encoded
        csr.signatureAlgorithm shouldBe signatureAlgorithm
        csr.tbsCsr.version shouldBe 0
        (csr.tbsCsr.subjectName.first().attrsAndValues.first().value as Asn1Primitive).content shouldBe commonName.encodeToByteArray()
        val parsedPublicKey = csr.tbsCsr.publicKey
        parsedPublicKey.shouldBeInstanceOf<CryptoPublicKey.EC>()
        parsedPublicKey.xBytes shouldBe keyX
        parsedPublicKey.yBytes shouldBe keyY
    }

    "Equals & hashCode" {

        /*
            TbsCertificationRequest
        */
        val ecPublicKey1 = keyPair.public as ECPublicKey
        val cryptoPublicKey1 = ecPublicKey1.toCryptoPublicKey().getOrThrow()
        val ecPublicKey11 = keyPair.public as ECPublicKey
        val cryptoPublicKey11 = ecPublicKey11.toCryptoPublicKey().getOrThrow()
        val ecPublicKey2 = keyPair1.public as ECPublicKey
        val cryptoPublicKey2 = ecPublicKey2.toCryptoPublicKey().getOrThrow()

        val commonName = "DefaultCryptoService"
        val commonName1 = "DefaultCryptoService1"

        val tbsCsr1 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey1
        )
        val tbsCsr11 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey1
        )
        val tbsCsr111 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName1)))),
            publicKey = cryptoPublicKey1
        )
        val tbsCsr12 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey11
        )
        val tbsCsr122 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName1)))),
            publicKey = cryptoPublicKey11
        )
        val tbsCsr2 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey2
        )
        val tbsCsr22 = TbsCertificationRequest(
            version = 1,
            subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
            publicKey = cryptoPublicKey2
        )

        // equals and hashCode
        tbsCsr1 shouldBe tbsCsr1
        tbsCsr1 shouldBe tbsCsr11
        tbsCsr1 shouldNotBe tbsCsr111
        tbsCsr1 shouldBe tbsCsr12
        tbsCsr12 shouldNotBe tbsCsr122
        tbsCsr1 shouldNotBe tbsCsr2
        tbsCsr2 shouldBe tbsCsr2
        tbsCsr2 shouldNotBe tbsCsr22

        tbsCsr1.hashCode() shouldBe tbsCsr1.hashCode()
        tbsCsr1.hashCode() shouldBe tbsCsr11.hashCode()
        tbsCsr1.hashCode() shouldNotBe tbsCsr111.hashCode()
        tbsCsr1.hashCode() shouldBe tbsCsr12.hashCode()
        tbsCsr12.hashCode() shouldNotBe tbsCsr122.hashCode()
        tbsCsr1.hashCode() shouldNotBe tbsCsr2.hashCode()
        tbsCsr2.hashCode() shouldBe tbsCsr2.hashCode()
        tbsCsr2.hashCode() shouldNotBe tbsCsr22.hashCode()

        /*
            Pkcs10CertificationRequest
        */
        val signatureAlgorithm1 = X509SignatureAlgorithm.ES256
        val signatureAlgorithm2 = X509SignatureAlgorithm.ES512

        val signed = signatureAlgorithm1.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCsr1.encodeToDer())
        }.sign()
        val signed1 = signatureAlgorithm1.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCsr1.encodeToDer())
        }.sign()
        val signed11 = signatureAlgorithm2.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair.private)
            update(tbsCsr1.encodeToDer())
        }.sign()
        val signed2 = signatureAlgorithm1.getJCASignatureInstance().getOrThrow().apply {
            initSign(keyPair1.private)
            update(tbsCsr2.encodeToDer())
        }.sign()

        val csr = Pkcs10CertificationRequest(
            tbsCsr1,
            signatureAlgorithm1,
            CryptoSignature.parseFromJca(signed, signatureAlgorithm1)
        )
        val csr1 = Pkcs10CertificationRequest(
            tbsCsr1,
            signatureAlgorithm1,
            CryptoSignature.parseFromJca(signed1, signatureAlgorithm1)
        )
        val csr11 = Pkcs10CertificationRequest(
            tbsCsr1,
            signatureAlgorithm2,
            CryptoSignature.parseFromJca(signed11, signatureAlgorithm2)
        )
        val csr2 = Pkcs10CertificationRequest(
            tbsCsr2,
            signatureAlgorithm1,
            CryptoSignature.parseFromJca(signed2, signatureAlgorithm1)
        )

        csr shouldNotBe csr1
        csr1 shouldBe csr1
        csr11 shouldBe csr11
        csr2 shouldBe csr2
        csr1 shouldNotBe csr11
        csr1 shouldNotBe csr2

        csr.hashCode() shouldNotBe csr1.hashCode()
        csr1.hashCode() shouldBe csr1.hashCode()
        csr11.hashCode() shouldBe csr11.hashCode()
        csr2.hashCode() shouldBe csr2.hashCode()
        csr1.hashCode() shouldNotBe csr11.hashCode()
        csr1.hashCode() shouldNotBe csr2.hashCode()

        /*
            Pkcs10CertificationRequestAttribute
        */

        val keyUsage = KeyUsage(KeyUsage.digitalSignature)
        val extendedKeyUsage = ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)

        val attr1 =
            Pkcs10CertificationRequestAttribute(
                ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"),
                1337.encodeToAsn1Primitive()
            )
        val attr11 =
            Pkcs10CertificationRequestAttribute(
                ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"),
                1337.encodeToAsn1Primitive()
            )
        val attr12 =
            Pkcs10CertificationRequestAttribute(
                ObjectIdentifier("1.2.1840.13549.1.9.16.1337.27"),
                1337.encodeToAsn1Primitive()
            )
        val attr13 =
            Pkcs10CertificationRequestAttribute(
                ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"),
                1338.encodeToAsn1Primitive()
            )
        val attr2 = Pkcs10CertificationRequestAttribute(KnownOIDs.keyUsage, Asn1Element.parse(keyUsage.encoded))
        val attr3 =
            Pkcs10CertificationRequestAttribute(KnownOIDs.extKeyUsage, Asn1Element.parse(extendedKeyUsage.encoded))

        attr1 shouldBe attr1
        attr1 shouldBe attr11
        attr1 shouldNotBe attr12
        attr1 shouldNotBe attr13
        attr1 shouldNotBe attr2
        attr2 shouldNotBe attr3

        attr1.hashCode() shouldBe attr1.hashCode()
        attr1.hashCode() shouldBe attr11.hashCode()
        attr1.hashCode() shouldNotBe attr12.hashCode()
        attr1.hashCode() shouldNotBe attr13.hashCode()
        attr1.hashCode() shouldNotBe attr2.hashCode()
        attr2.hashCode() shouldNotBe attr3.hashCode()

    }
}
