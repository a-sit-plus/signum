package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.Asn1Element
import at.asitplus.crypto.datatypes.asn1.Asn1EncapsulatingOctetString
import at.asitplus.crypto.datatypes.asn1.Asn1Primitive
import at.asitplus.crypto.datatypes.asn1.Asn1Sequence
import at.asitplus.crypto.datatypes.asn1.Asn1String
import at.asitplus.crypto.datatypes.asn1.KnownOIDs
import at.asitplus.crypto.datatypes.asn1.ObjectIdentifier
import at.asitplus.crypto.datatypes.asn1.encodeToTlv
import at.asitplus.crypto.datatypes.asn1.ensureSize
import at.asitplus.crypto.datatypes.asn1.parse
import at.asitplus.crypto.datatypes.pki.DistinguishedName
import at.asitplus.crypto.datatypes.pki.Pkcs10CertificationRequest
import at.asitplus.crypto.datatypes.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.crypto.datatypes.pki.TbsCertificationRequest
import at.asitplus.crypto.datatypes.pki.X509CertificateExtension
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ExtensionsGenerator
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey


class Pkcs10CertificationRequestJvmTest : FreeSpec({

    lateinit var ecCurve: EcCurve
    lateinit var keyPair: KeyPair
    lateinit var keyPair1: KeyPair

    beforeTest {
        ecCurve = EcCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
        keyPair1 = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
    }

    "CSR match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaPublicKey(ecPublicKey).getOrThrow()

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = CryptoAlgorithm.ES256


        val tbsCsr = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey
        )
        val signed = Signature.getInstance(signatureAlgorithm.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToDer())
        }.sign()
        val csr = Pkcs10CertificationRequest(tbsCsr, signatureAlgorithm, signed)

        val kotlinEncoded = csr.encodeToDer()

        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
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
        val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaPublicKey(ecPublicKey).getOrThrow()

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = CryptoAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val keyUsage = KeyUsage(KeyUsage.digitalSignature)
        val extendedKeyUsage = ExtendedKeyUsage(KeyPurposeId.anyExtendedKeyUsage)
        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki)
            .addAttribute(Extension.keyUsage, keyUsage)
            .addAttribute(Extension.extendedKeyUsage, extendedKeyUsage)
            .build(contentSigner)
        val tbsCsr = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey,
            attributes = listOf(
                Pkcs10CertificationRequestAttribute(KnownOIDs.keyUsage, Asn1Element.parse(keyUsage.encoded)),
                Pkcs10CertificationRequestAttribute(
                    KnownOIDs.`extKeyUsage`,
                    Asn1Element.parse(extendedKeyUsage.encoded)
                )
            )
        )
        val signed = Signature.getInstance(signatureAlgorithm.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToTlv().derEncoded)
        }.sign()
        val csr = Pkcs10CertificationRequest(tbsCsr, signatureAlgorithm, signed)

        val kotlinEncoded = csr.encodeToTlv().derEncoded
        val jvmEncoded = bcCsr.encoded
        // CSR will never entirely match because of randomness in ECDSA signature
        //kotlinEncoded shouldBe jvmEncoded
        kotlinEncoded.drop(6).take(172) shouldBe jvmEncoded.drop(6).take(172)

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSRs with extensionRequest match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaPublicKey(ecPublicKey).getOrThrow()

        // create CSR with bouncycastle
        val commonName = "localhost"
        val signatureAlgorithm = CryptoAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
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
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey,
            extensions = listOf(
                X509CertificateExtension(
                    KnownOIDs.keyUsage,
                    value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(keyUsage.encoded))),
                    critical = true
                ),
                X509CertificateExtension(
                    KnownOIDs.`extKeyUsage`,
                    value = Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(extendedKeyUsage.encoded))),
                    critical = true
                )
            ),
            attributes = listOf(
                Pkcs10CertificationRequestAttribute(
                    ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"),
                    1337.encodeToTlv()
                )
            )
        )
        val signed = Signature.getInstance(signatureAlgorithm.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToTlv().derEncoded)
        }.sign()
        val csr = Pkcs10CertificationRequest(tbsCsr, signatureAlgorithm, signed)

        val kotlinEncoded = csr.encodeToTlv().derEncoded
        val jvmEncoded = bcCsr.encoded
        // CSR will never entirely match because of randomness in ECDSA signature
        //kotlinEncoded shouldBe jvmEncoded
        kotlinEncoded.drop(6).take(172) shouldBe jvmEncoded.drop(6).take(172)

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSR can be parsed" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = CryptoAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki).build(contentSigner)

        val csr = Pkcs10CertificationRequest.decodeFromTlv(Asn1Element.parse(bcCsr.encoded) as Asn1Sequence)
        csr.shouldNotBeNull()

        //x509Certificate.encodeToDer() shouldBe certificateHolder.encoded
        csr.signatureAlgorithm shouldBe signatureAlgorithm
        csr.tbsCsr.version shouldBe 0
        (csr.tbsCsr.subjectName.first().value as Asn1Primitive).content shouldBe commonName.encodeToByteArray()
        val parsedPublicKey = csr.tbsCsr.publicKey
        parsedPublicKey.shouldBeInstanceOf<CryptoPublicKey.Ec>()
        parsedPublicKey.x shouldBe keyX
        parsedPublicKey.y shouldBe keyY
    }

    "Equals & hashCode" {

        /*
            TbsCertificationRequest
        */
        val ecPublicKey1 = keyPair.public as ECPublicKey
        val cryptoPublicKey1 = CryptoPublicKey.Ec.fromJcaPublicKey(ecPublicKey1).getOrThrow()
        val ecPublicKey11 = keyPair.public as ECPublicKey
        val cryptoPublicKey11 = CryptoPublicKey.Ec.fromJcaPublicKey(ecPublicKey11).getOrThrow()
        val ecPublicKey2 = keyPair1.public as ECPublicKey
        val cryptoPublicKey2 = CryptoPublicKey.Ec.fromJcaPublicKey(ecPublicKey2).getOrThrow()

        val commonName = "DefaultCryptoService"
        val commonName1 = "DefaultCryptoService1"

        val tbsCsr1 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey1
        )
        val tbsCsr11 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey1
        )
        val tbsCsr111 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName1))),
            publicKey = cryptoPublicKey1
        )
        val tbsCsr12 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey11
        )
        val tbsCsr122 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName1))),
            publicKey = cryptoPublicKey11
        )
        val tbsCsr2 = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey2
        )
        val tbsCsr22 = TbsCertificationRequest(
            version = 1,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
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
        val signatureAlgorithm1 = CryptoAlgorithm.ES256
        val signatureAlgorithm2 = CryptoAlgorithm.ES512

        val signed = Signature.getInstance(signatureAlgorithm1.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr1.encodeToDer())
        }.sign()
        val signed1 = Signature.getInstance(signatureAlgorithm1.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr1.encodeToDer())
        }.sign()
        val signed11 = Signature.getInstance(signatureAlgorithm2.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr1.encodeToDer())
        }.sign()
        val signed2 = Signature.getInstance(signatureAlgorithm1.jcaName).apply {
            initSign(keyPair1.private)
            update(tbsCsr2.encodeToDer())
        }.sign()

        val csr = Pkcs10CertificationRequest(tbsCsr1, signatureAlgorithm1, signed)
        val csr1 = Pkcs10CertificationRequest(tbsCsr1, signatureAlgorithm1, signed1)
        val csr11 = Pkcs10CertificationRequest(tbsCsr1, signatureAlgorithm2, signed11)
        val csr2 = Pkcs10CertificationRequest(tbsCsr2, signatureAlgorithm1, signed2)

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
            Pkcs10CertificationRequestAttribute(ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"), 1337.encodeToTlv())
        val attr11 =
            Pkcs10CertificationRequestAttribute(ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"), 1337.encodeToTlv())
        val attr12 =
            Pkcs10CertificationRequestAttribute(ObjectIdentifier("1.2.1840.13549.1.9.16.1337.27"), 1337.encodeToTlv())
        val attr13 =
            Pkcs10CertificationRequestAttribute(ObjectIdentifier("1.2.1840.13549.1.9.16.1337.26"), 1338.encodeToTlv())
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
})
