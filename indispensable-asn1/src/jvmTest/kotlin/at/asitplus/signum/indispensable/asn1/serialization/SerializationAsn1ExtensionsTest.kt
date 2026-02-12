package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.toCryptoPrivateKey
import at.asitplus.signum.indispensable.toCryptoPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.Asn1Null
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1Primitive
import at.asitplus.signum.indispensable.asn1.serialization.api.DER
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequestAttribute
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509CertificateExtension
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import de.infix.testBalloon.framework.core.TestConfig
import de.infix.testBalloon.framework.core.TestSession.Companion.DefaultConfiguration
import de.infix.testBalloon.framework.core.invocation
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.random.Random

@OptIn(ExperimentalStdlibApi::class)
val SerializationTestAsn1Extensions by testSuite(
    testConfig = DefaultConfiguration.invocation(TestConfig.Invocation.Sequential)
) {
    "ASN.1 specific extensions to overpower star projection limitations" - {
        "EC-256 Key Generation and Signing" {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            val ecGenParameterSpec = ECGenParameterSpec("secp256r1")
            keyPairGenerator.initialize(ecGenParameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()

            val privateKey = keyPair.private
            val publicKey = keyPair.public

            val signumPrivateKey = privateKey.toCryptoPrivateKey().getOrThrow()
            val signumPublicKey = publicKey.toCryptoPublicKey().getOrThrow()

            signumPrivateKey.encodeToDer() shouldBe DER.encodeToDer(signumPrivateKey)
            DER.decodeFromDer<CryptoPrivateKey>(signumPrivateKey.encodeToDer()) shouldBe signumPrivateKey
            DER.decodeFromDer<CryptoPrivateKey.WithPublicKey<*>>(signumPrivateKey.encodeToDer()) shouldBe signumPrivateKey

            DER.decodeFromTlv<CryptoPrivateKey>(signumPrivateKey.encodeToTlv()) shouldBe signumPrivateKey
            DER.decodeFromTlv<CryptoPrivateKey.WithPublicKey<*>>(signumPrivateKey.encodeToTlv()) shouldBe signumPrivateKey

            signumPublicKey.encodeToDer() shouldBe DER.encodeToDer(signumPublicKey)
            DER.decodeFromDer<CryptoPublicKey>(signumPublicKey.encodeToDer()) shouldBe signumPublicKey
            DER.decodeFromTlv<CryptoPublicKey>(signumPublicKey.encodeToTlv()) shouldBe signumPublicKey

            val dataToSign = Random.nextBytes(32)

            val signature = Signature.getInstance("SHA256withECDSA")

            signature.initSign(privateKey)
            signature.update(dataToSign)
            val signatureBytes = signature.sign()

            val signumSig = CryptoSignature.decodeFromDer(signatureBytes).shouldBeInstanceOf<CryptoSignature.EC>()
            DER.decodeFromDer<CryptoSignature>(signatureBytes) shouldBe signumSig
        }

        "CSR" {
            val keyPairGenerator = KeyPairGenerator.getInstance("EC")
            val ecGenParameterSpec = ECGenParameterSpec("secp256r1")
            keyPairGenerator.initialize(ecGenParameterSpec)
            val keyPair = keyPairGenerator.generateKeyPair()

            val privateKey = keyPair.private
            val publicKey = keyPair.public

            val signumPublicKey = publicKey.toCryptoPublicKey().getOrThrow()

            val tbsCSR = TbsCertificationRequest(
                subjectName = listOf(
                    RelativeDistinguishedName(AttributeTypeAndValue.CommonName("AT".encodeToAsn1Primitive()))
                ),
                publicKey = signumPublicKey,
                extensions = listOf(
                    X509CertificateExtension(
                        KnownOIDs.basicConstraints,
                        critical = true,
                        value = Asn1EncapsulatingOctetString(listOf(Asn1Null))
                    )
                ),
                attributes = listOf(
                    Pkcs10CertificationRequestAttribute(
                        KnownOIDs.extensions,
                        3.encodeToAsn1Primitive()
                    )
                )
            )
            val encoded = DER.encodeToDer(tbsCSR)
            encoded shouldBe tbsCSR.encodeToDer()
            DER.decodeFromDer<TbsCertificationRequest>(encoded) shouldBe tbsCSR

            val signature = Signature.getInstance("SHA256withECDSA")

            signature.initSign(privateKey)
            signature.update(encoded)
            val signatureBytes = signature.sign()

            val signumSig = CryptoSignature.decodeFromDer(signatureBytes).shouldBeInstanceOf<CryptoSignature.EC>()

            val csr = Pkcs10CertificationRequest(
                tbsCSR,
                X509SignatureAlgorithm.ES256,
                signumSig
            )

            val csrEncoded = DER.encodeToDer(csr)
            csrEncoded shouldBe csr.encodeToDer()
            DER.decodeFromDer<Pkcs10CertificationRequest>(csrEncoded) shouldBe csr
        }
    }
}
