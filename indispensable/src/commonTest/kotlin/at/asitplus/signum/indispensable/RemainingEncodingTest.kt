@file:OptIn(SignumInternals::class)

package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.RsaSsaPssParams.Companion.invoke
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.ecPublicKey
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.signum.indispensable.sign.asn1
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.encodeToByteArray

val RemainingEncodingTest by matrixSuite {

    "Signatures use contextual DER and retain raw values until an algorithm is supplied" {
        val rsa = RsaSignature.fromRawSignatureValue(byteArrayOf(1, 2, 3))
        val signature: CryptoSignature = rsa
        val bytes = signature.asn1.toDer()
        RsaSignature.fromAsn1(bytes) shouldBe rsa
        val raw = AbstractSignature.fromAsn1(bytes)
        raw.asn1.toDer() shouldBe bytes
        raw.withSignatureAlgorithm(RsaAlgorithm.withSHA256andPKCS1Padding) shouldBe rsa
        val generic = CryptoSignature.fromAsn1(bytes)
        generic.asn1.toDer() shouldBe bytes
        shouldThrow<UnsupportedCryptoException> { generic.withSignatureAlgorithm(EcdsaAlgorithm.withSHA256) }

        shouldThrowAny { EcdsaSignature.fromRS(BigInteger.ZERO, BigInteger.ONE) }
        shouldThrowAny { EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.ZERO) }
        val ec = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        val ecBytes = ec.asn1.toDer()
        EcdsaSignature.fromAsn1(ecBytes).asn1.toDer() shouldBe ecBytes
        val definite = ec.withCurve(ECCurve.SECP_256_R_1)
        definite.asn1.toDer() shouldBe ecBytes
        EcdsaSignature.fromAsn1(ecBytes).shouldBeInstanceOf<EcdsaSignature.IndefiniteLength>()
            .withCurve(ECCurve.SECP_256_R_1) shouldBe definite
    }

    "CSR equality uses supplied semantics without requesting an X509 representation" {
        val name = Name.EMPTY
        val key = ECCurve.SECP_256_R_1.generator.asPublicKey()
        val tbs = TbsCertificationRequest(name, key, attributes = emptyList())
        val sameTbs = TbsCertificationRequest(name, key, attributes = emptyList())
        val signature: CryptoSignature = object : CryptoSignature {
            override val sourceRepresentation = SourceRepresentationStorage()
        }
        val csr = CertificationRequest(tbs, EcdsaAlgorithm.withSHA256, signature)
        val same = CertificationRequest(sameTbs, EcdsaAlgorithm.withSHA256, signature)
        csr.tbsCsr shouldBeSameInstanceAs tbs
        csr.tbsCsr.subjectName shouldBeSameInstanceAs name
        csr shouldBe same
        csr.hashCode() shouldBe same.hashCode()
        csr shouldNotBe CertificationRequest(tbs, EcdsaAlgorithm.withSHA384, signature)
        csr shouldNotBe CertificationRequest(tbs, EcdsaAlgorithm.withSHA256,
            EcdsaSignature.fromRS(BigInteger.TWO, BigInteger.ONE))
        shouldThrowAny { csr.asn1.toDer() }

        val encodable = CertificationRequest(
            TbsCertificationRequest(Name.EMPTY, key, attributes = emptyList()),
            EcdsaAlgorithm.withSHA256, EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO),
        )
        val bytes = encodable.asn1.toDer()
        val decoded = CertificationRequest.fromAsn1(bytes)
        decoded shouldBe encodable
        decoded.hashCode() shouldBe encodable.hashCode()
        decoded.asn1.toDer() shouldBe bytes
        val model = encodable.asn1.toRepresentation()
        val retained = CertificationRequest.fromAsn1(model)
        retained.asn1.toRepresentation() shouldBeSameInstanceAs model
        val inner = TbsCertificationRequest.fromAsn1(model.certificationRequestInfo)
        inner.asn1.toRepresentation() shouldBeSameInstanceAs model.certificationRequestInfo

        val unknownAlgorithm = model.copy(signatureAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null))
        val originalBytes = Signum.Der.encodeToByteArray(Pkcs10CertificationRequest.serializer(), unknownAlgorithm)
        val opaque = CertificationRequest.fromAsn1(originalBytes)
        opaque.asn1.toDer() shouldBe originalBytes
        opaque.tbsCsr.subjectName shouldBe Name.EMPTY
        opaque.tbsCsr.publicKey shouldBe key
        opaque.tbsCsr.asn1.toDer() shouldBe encodable.tbsCsr.asn1.toDer()
        shouldThrow<UnsupportedCryptoException> { opaque.signatureAlgorithm.preHashedSignatureFormat }
        shouldThrowAny { opaque.signature }
        opaque.asn1.toDer() shouldBe originalBytes

        val unknownKey = Pkcs10CertificationRequestInfo(
            subjectName = model.certificationRequestInfo.subjectName,
            publicKey = model.certificationRequestInfo.publicKey.copy(
                algorithmIdentifier = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null),
            ),
        )
        val opaqueTbs = TbsCertificationRequest.fromAsn1(unknownKey)
        opaqueTbs.subjectName shouldBe Name.EMPTY
        opaqueTbs.attributes shouldBe emptyList()
        shouldThrow<UnsupportedCryptoException> { opaqueTbs.publicKey.didEncoded }
        opaqueTbs.asn1.toRepresentation() shouldBeSameInstanceAs unknownKey
    }

    "Only decoded values retain a source and other encodings leave it unchanged" {
        val ecSignature = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        ecSignature.realSourceRepresentation shouldBe null
        val signatureModel = ecSignature.asn1.toRepresentation()
        EcdsaSignature.fromAsn1(signatureModel).asn1.toRepresentation().rawBitString shouldBeSameInstanceAs signatureModel.rawBitString
        val rsaModel = RsaSignature(byteArrayOf(1, 2, 3)).asn1.toRepresentation()
        RsaSignature.fromAsn1(rsaModel).asn1.toRepresentation().rawBitString shouldBeSameInstanceAs rsaModel.rawBitString

        val pss = RsaAlgorithm.Parameters.PssPadded(digest = Digest.SHA256)
        pss.realSourceRepresentation shouldBe null
        val pssModel = pss.asn1.toRepresentation()
        RsaAlgorithm.Parameters.PssPadded.fromAsn1(pssModel).asn1.toRepresentation() shouldBeSameInstanceAs pssModel

        val key = EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1)
        key.realSourceRepresentation shouldBe null
        val pkcs8 = key.asn1.toRepresentation()
        val decoded = EcdsaPrivateKey.fromAsn1(pkcs8)
        decoded.asn1.toRepresentation() shouldBeSameInstanceAs pkcs8
        decoded shouldBe key
        val sec1 = key.asn1.sec1.toRepresentation()
        val fromSec1 = EcdsaPrivateKey.fromAsn1.SEC1(sec1)
        fromSec1.asn1.sec1.toRepresentation() shouldBeSameInstanceAs sec1
        fromSec1 shouldBe key
        fromSec1.asn1.toDer() shouldBe key.asn1.toDer()
        fromSec1.realSourceRepresentation shouldBeSameInstanceAs sec1
        decoded.realSourceRepresentation shouldBeSameInstanceAs pkcs8
        key.realSourceRepresentation shouldBe null
        ecSignature.realSourceRepresentation shouldBe null
        pss.realSourceRepresentation shouldBe null


    }

    "MACs and PSS parameters use their structural codecs" {
        Digest.fromAsn1(Digest.SHA256.asn1.toDer()) shouldBe Digest.SHA256
        MessageAuthenticationCode.fromAsn1(HMAC.SHA256.asn1.toDer()) shouldBe HMAC.SHA256
        val mac: MessageAuthenticationCode = HMAC.SHA256
        MessageAuthenticationCode.fromAsn1(mac.asn1.toDer()) shouldBe mac
        shouldThrowAny { mac.truncatedTo(128.bit).asn1.toDer() }
        val params = RsaAlgorithm.Parameters.PssPadded(digest = Digest.SHA384)
        RsaAlgorithm.Parameters.PssPadded.fromAsn1(params.asn1.toTlv()) shouldBe params
        val parameters: RsaAlgorithm.Parameters<at.asitplus.awesn1.crypto.RsaSsaPssParams> = params
        RsaAlgorithm.Parameters.PssPadded.fromAsn1(
            parameters.asn1.toDer(),
        ) shouldBe params
        val mgf = RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(Digest.SHA256)
        RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.fromAsn1(mgf.asn1.toDer()) shouldBe mgf
    }

    "Generic signature algorithms defer unsupported PSS digest and MGF identifiers until usage" {
        val unknown = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null)
        val original = RsaSsaPssParams(hashAlgorithm = unknown, maskGenAlgorithm = unknown, saltLength = 42)
        val model = X509AlgorithmIdentifier(original, Signum.Der)
        val decoded = SignatureAlgorithm.fromAsn1(model)
        shouldThrow<UnsupportedCryptoException> { decoded.preHashedSignatureFormat }
        decoded.asn1.toRepresentation().element shouldBeSameInstanceAs model.element
    }

    "EC private key decoders reject unsupported curves while generic decoding retains the source" {
        val unknownCurve = ObjectIdentifier("1.2.3.4")
        val original = Sec1EcPrivateKeyInfo(
            privateKey = ByteArray(32).apply { this[lastIndex] = 1 },
            parameters = unknownCurve, publicKey = null,
        )
        shouldThrowAny { EcdsaPrivateKey.fromAsn1.SEC1(original) }

        val pkcs8 = Pkcs8PrivateKeyInfo(
            privateKeyAlgorithm = X509AlgorithmIdentifier(KnownOIDs.ecPublicKey, Signum.Der.encodeToTlv(unknownCurve)),
            privateKey = Asn1OctetString(Signum.Der.encodeToByteArray(original)),
        )
        shouldThrowAny { EcdsaPrivateKey.fromAsn1(pkcs8) }
        val fromPkcs8 = CryptoPrivateKey.fromAsn1(pkcs8)
        fromPkcs8.asn1.toRepresentation() shouldBeSameInstanceAs pkcs8
        fromPkcs8.asn1.toDer() shouldBe Signum.Der.encodeToByteArray(pkcs8)
    }
}
