package at.asitplus.signum.indispensable

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val RemainingEncodingTest by matrixSuite {
    val der = DER { serializersModule = signumAsn1Serializers }

    "Signatures use contextual DER and retain raw values until an algorithm is supplied" {
        val rsa = RsaSignature.fromRawSignatureValue(byteArrayOf(1, 2, 3))
        val signature: CryptoSignature = rsa
        val bytes = der.encodeToByteArray(signature)
        der.decodeFromByteArray<RsaSignature>(bytes) shouldBe rsa
        val raw = der.decodeFromByteArray<SignatureValue>(bytes)
        der.encodeToByteArray(raw) shouldBe bytes
        raw.withSignatureAlgorithm(RsaAlgorithm.withSHA256andPKCS1Padding) shouldBe rsa
        shouldThrowAny { der.decodeFromByteArray<CryptoSignature>(bytes) }

        val ec = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        val ecBytes = der.encodeToByteArray(ec)
        der.encodeToByteArray(der.decodeFromByteArray<EcdsaSignature>(ecBytes)) shouldBe ecBytes
        val definite = ec.withCurve(ECCurve.SECP_256_R_1)
        der.encodeToByteArray(definite) shouldBe ecBytes
        shouldThrowAny { der.decodeFromByteArray<EcdsaSignature.DefiniteLength>(ecBytes) }
    }

    "CSR equality uses supplied semantics without requesting an X509 representation" {
        val name: Name = object : Name {
            override val relativeDistinguishedNames = emptyList<RelativeDistinguishedName>()
        }
        val key = ECCurve.SECP_256_R_1.generator.asPublicKey()
        val tbs = TbsCertificationRequest(name, key, attributes = emptyList())
        val sameTbs = TbsCertificationRequest(name, key, attributes = emptyList())
        val signature = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        val csr = CertificationRequest(tbs, EcdsaAlgorithm.withSHA256, signature)
        val same = CertificationRequest(sameTbs, EcdsaAlgorithm.withSHA256, signature)
        csr.tbsCsr shouldBeSameInstanceAs tbs
        csr.tbsCsr.subjectName shouldBeSameInstanceAs name
        csr shouldBe same
        csr.hashCode() shouldBe same.hashCode()
        csr shouldNotBe CertificationRequest(tbs, EcdsaAlgorithm.withSHA384, signature)
        csr shouldNotBe CertificationRequest(tbs, EcdsaAlgorithm.withSHA256,
            EcdsaSignature.fromRS(BigInteger.TWO, BigInteger.ONE))
        shouldThrowAny { der.encodeToByteArray(csr) }

        val encodable = CertificationRequest(
            TbsCertificationRequest(X500Name.EMPTY, key, attributes = emptyList()),
            EcdsaAlgorithm.withSHA256, signature,
        )
        val bytes = der.encodeToByteArray(encodable)
        val decoded = der.decodeFromByteArray<CertificationRequest>(bytes)
        decoded shouldBe encodable
        decoded.hashCode() shouldBe encodable.hashCode()
        der.encodeToByteArray(decoded) shouldBe bytes
        val model = encodable.asn1Representation
        val retained = CertificationRequest.fromAsn1Representation(model)
        retained.representations[X509] shouldBeSameInstanceAs model
        retained.asn1Representation shouldBeSameInstanceAs model
        val inner = TbsCertificationRequest.fromAsn1Representation(model.certificationRequestInfo)
        inner.asn1Representation shouldBeSameInstanceAs model.certificationRequestInfo

        val unknownAlgorithm = model.copy(signatureAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null))
        val originalBytes = der.encodeToByteArray(Pkcs10CertificationRequest.serializer(), unknownAlgorithm)
        val opaque = der.decodeFromByteArray<CertificationRequest>(originalBytes)
        der.encodeToByteArray(opaque) shouldBe originalBytes
        shouldThrowAny { opaque.signatureAlgorithm }
    }

    "Alternative names compare their contents without encoding them" {
        val name: GeneralName = object : GeneralName {
            override fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName = this
        }
        val first = AlternativeNames.fromGeneralNames(listOf(name))
        val second = AlternativeNames.fromGeneralNames(listOf(name))
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        first shouldNotBe AlternativeNames.fromGeneralNames(emptyList())
        shouldThrowAny { der.encodeToByteArray(first) }
    }

    "Original models are retained in maps and fresh models come from semantic fields" {
        val ecSignature = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        ecSignature.representations shouldBe emptyMap()
        val signatureModel = ecSignature.asn1Representation
        EcdsaSignature.fromAsn1Representation(signatureModel).asn1Representation.rawBitString shouldBeSameInstanceAs signatureModel.rawBitString
        val rsaModel = RsaSignature(byteArrayOf(1, 2, 3)).asn1Representation
        RsaSignature.fromAsn1Representation(rsaModel).asn1Representation.rawBitString shouldBeSameInstanceAs rsaModel.rawBitString

        val pss = RsaAlgorithm.Parameters.PssPadded(digest = Digest.SHA256)
        pss.representations shouldBe emptyMap()
        val pssModel = pss.asn1Representation
        RsaAlgorithm.Parameters.PssPadded.fromAsn1Representation(pssModel).asn1Representation shouldBeSameInstanceAs pssModel

        val key = EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1,
            encodeCurve = true, encodePublicKey = true)
        key.representations shouldBe emptyMap()
        val pkcs8 = key.asPKCS8
        val decoded = EcdsaPrivateKey.fromAsn1Representation(pkcs8)
        decoded.asPKCS8 shouldBeSameInstanceAs pkcs8
        decoded shouldBe key
        val sec1 = key.asSEC1
        val fromSec1 = EcdsaPrivateKey.fromAsn1Representation(sec1)
        fromSec1.asSEC1 shouldBeSameInstanceAs sec1
        fromSec1 shouldBe key
        der.encodeToByteArray(fromSec1) shouldBe der.encodeToByteArray(key)
        fromSec1.attributes shouldBe null

        val names = AlternativeNames.fromGeneralNames(emptyList())
        names.representations shouldBe emptyMap()
        val namesModel = requireNotNull(names.asn1Representation)
        requireNotNull(AlternativeNames.fromAsn1Representation(namesModel).asn1Representation).entries shouldBeSameInstanceAs namesModel.entries
    }

    "MACs and PSS parameters use their structural codecs" {
        der.decodeFromByteArray<Digest>(der.encodeToByteArray(Digest.SHA256)) shouldBe Digest.SHA256
        der.decodeFromByteArray<HMAC>(der.encodeToByteArray(HMAC.SHA256)) shouldBe HMAC.SHA256
        val mac: MessageAuthenticationCode = HMAC.SHA256
        der.decodeFromByteArray<MessageAuthenticationCode>(der.encodeToByteArray(mac)) shouldBe mac
        shouldThrowAny { der.encodeToByteArray(mac.truncatedTo(128.bit)) }
        val params = RsaAlgorithm.Parameters.PssPadded(digest = Digest.SHA384)
        der.decodeFromTlv<RsaAlgorithm.Parameters.PssPadded>(der.encodeToTlv(params)) shouldBe params
        val parameters: RsaAlgorithm.Parameters<at.asitplus.awesn1.crypto.RsaSsaPssParams> = params
        der.decodeFromByteArray<RsaAlgorithm.Parameters<at.asitplus.awesn1.crypto.RsaSsaPssParams>>(
            der.encodeToByteArray(parameters),
        ) shouldBe params
        val mgf = RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(Digest.SHA256)
        der.decodeFromByteArray<RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1>(der.encodeToByteArray(mgf)) shouldBe mgf
    }

    "Encoding independent names have no X509 marker and fail only when encoding is requested" {
        val name: Name = object : Name {
            override val relativeDistinguishedNames = emptyList<RelativeDistinguishedName>()
        }
        name.asn1Representation shouldBe null
        shouldThrowAny { der.encodeToByteArray(name) }
        val generalName: GeneralName = object : GeneralName {
            override fun createValidatedCopy(validate: (GeneralName) -> Boolean): GeneralName = this
        }
        generalName.asn1Representation shouldBe null
        shouldThrowAny { der.encodeToByteArray(generalName) }
    }
}
