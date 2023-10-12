import at.asitplus.crypto.datatypes.*
import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.pki.CertificationRequest
import at.asitplus.crypto.datatypes.pki.DistinguishedName
import at.asitplus.crypto.datatypes.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.crypto.datatypes.pki.TbsCertificationRequest
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
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

    beforeTest {
        ecCurve = EcCurve.SECP_256_R_1
        keyPair = KeyPairGenerator.getInstance("EC").also {
            it.initialize(256)
        }.genKeyPair()
    }

    "CSR match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaKey(ecPublicKey)
        cryptoPublicKey.shouldNotBeNull()

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = JwsAlgorithm.ES256


        val tbsCsr = TbsCertificationRequest(
            version = 0,
            subjectName = listOf(DistinguishedName.CommonName(Asn1String.UTF8(commonName))),
            publicKey = cryptoPublicKey
        )
        val signed = Signature.getInstance(signatureAlgorithm.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr.derEncoded)
        }.sign()
        val csr = CertificationRequest(tbsCsr, signatureAlgorithm, signed)

        println(csr.derEncoded.encodeToString(Base16))

        val kotlinEncoded = csr.derEncoded

        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki).build(contentSigner)

        val jvmEncoded = bcCsr.encoded
        println("CSR will never entirely match because of randomness in ECDSA signature")
        //kotlinEncoded shouldBe jvmEncoded
        println(kotlinEncoded.encodeToString(Base16()))
        println(jvmEncoded.encodeToString(Base16()))
        kotlinEncoded.drop(6).take(142) shouldBe jvmEncoded.drop(6).take(142)

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSR with extensions match" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val cryptoPublicKey = CryptoPublicKey.Ec.fromJcaKey(ecPublicKey)
        cryptoPublicKey.shouldNotBeNull()

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = JwsAlgorithm.ES256
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
            extensions = listOf(
                Pkcs10CertificationRequestAttribute(KnownOIDs.keyUsage, Asn1Element.parse(keyUsage.encoded)),
                Pkcs10CertificationRequestAttribute(KnownOIDs.extKeyUsage, Asn1Element.parse(extendedKeyUsage.encoded))
            )
        )
        val signed = Signature.getInstance(signatureAlgorithm.jcaName).apply {
            initSign(keyPair.private)
            update(tbsCsr.encodeToTlv().derEncoded)
        }.sign()
        val csr = CertificationRequest(tbsCsr, signatureAlgorithm, signed)

        val kotlinEncoded = csr.encodeToTlv().derEncoded
        val jvmEncoded = bcCsr.encoded
        println("CSR will never entirely match because of randomness in ECDSA signature")
        //kotlinEncoded shouldBe jvmEncoded
        println(kotlinEncoded.encodeToString(Base16()))
        println(jvmEncoded.encodeToString(Base16()))
        kotlinEncoded.drop(6).take(172) shouldBe jvmEncoded.drop(6).take(172)

        val parsedFromKotlinCsr = PKCS10CertificationRequest(kotlinEncoded)
        parsedFromKotlinCsr.isSignatureValid(JcaContentVerifierProviderBuilder().build(keyPair.public))
    }

    "CSR can be parsed" {
        val ecPublicKey = keyPair.public as ECPublicKey
        val keyX = ecPublicKey.w.affineX.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val keyY = ecPublicKey.w.affineY.toByteArray().ensureSize(ecCurve.coordinateLengthBytes)
        val cryptoPublicKey = CryptoPublicKey.Ec(curve = ecCurve, x = keyX, y = keyY)

        // create CSR with bouncycastle
        val commonName = "DefaultCryptoService"
        val signatureAlgorithm = JwsAlgorithm.ES256
        val contentSigner: ContentSigner = JcaContentSignerBuilder(signatureAlgorithm.jcaName).build(keyPair.private)
        val spki = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val bcCsr = PKCS10CertificationRequestBuilder(X500Name("CN=$commonName"), spki).build(contentSigner)

        val csr = CertificationRequest.decodeFromTlv(Asn1Element.parse(bcCsr.encoded) as Asn1Sequence)
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

})