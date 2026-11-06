package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.Sec1EcPrivateKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequestInfo
import at.asitplus.awesn1.ecPublicKey
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.SignumInternals
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

    "Signatures use contextual DER and retain raw values until an algorithm is supplied" {
        val rsa = RsaSignature.fromRawSignatureValue(byteArrayOf(1, 2, 3))
        val signature: CryptoSignature = rsa
        val bytes = signature.toAsn1.DER()
        // TODO: restore from asn1 for rsasignature etc
        // RsaSignature.fromAsn1Representation(bytes) shouldBe rsa
        val raw = AbstractSignature.fromAsn1(bytes)
        der.encodeToByteArray(raw) shouldBe bytes
        raw.withSignatureAlgorithm(RsaAlgorithm.withSHA256andPKCS1Padding) shouldBe rsa
        shouldThrowAny { der.decodeFromByteArray<CryptoSignature>(bytes) }

        shouldThrowAny { EcdsaSignature.fromRS(BigInteger.ZERO, BigInteger.ONE) }
        shouldThrowAny { EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.ZERO) }
        val ec = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        val ecBytes = der.encodeToByteArray(ec)
        der.encodeToByteArray(der.decodeFromByteArray<EcdsaSignature>(ecBytes)) shouldBe ecBytes
        val definite = ec.withCurve(ECCurve.SECP_256_R_1)
        der.encodeToByteArray(definite) shouldBe ecBytes
        shouldThrowAny { der.decodeFromByteArray<EcdsaSignature.DefiniteLength>(ecBytes) }
    }

    "CSR equality uses supplied semantics without requesting an X509 representation" {
        val name = Name.EMPTY
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
            TbsCertificationRequest(Name.EMPTY, key, attributes = emptyList()),
            EcdsaAlgorithm.withSHA256, signature,
        )
        val bytes = der.encodeToByteArray(encodable)
        val decoded = der.decodeFromByteArray<CertificationRequest>(bytes)
        decoded shouldBe encodable
        decoded.hashCode() shouldBe encodable.hashCode()
        der.encodeToByteArray(decoded) shouldBe bytes
        val model = encodable.toAsn1()
        val retained = CertificationRequest.fromAsn1(model)
        retained.toAsn1() shouldBeSameInstanceAs model
        val inner = TbsCertificationRequest.fromAsn1(model.certificationRequestInfo)
        inner.toAsn1() shouldBeSameInstanceAs model.certificationRequestInfo

        val unknownAlgorithm = model.copy(signatureAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null))
        val originalBytes = der.encodeToByteArray(Pkcs10CertificationRequest.serializer(), unknownAlgorithm)
        val opaque = der.decodeFromByteArray<CertificationRequest>(originalBytes)
        der.encodeToByteArray(opaque) shouldBe originalBytes
        opaque.tbsCsr.subjectName shouldBe Name.EMPTY
        opaque.tbsCsr.publicKey shouldBe key
        der.encodeToByteArray(opaque.tbsCsr) shouldBe der.encodeToByteArray(encodable.tbsCsr)
        shouldThrowAny { opaque.signatureAlgorithm }
        shouldThrowAny { opaque.signature }
        der.encodeToByteArray(opaque) shouldBe originalBytes

        val unknownKey = Pkcs10CertificationRequestInfo(
            subjectName = model.certificationRequestInfo.subjectName,
            publicKey = model.certificationRequestInfo.publicKey.copy(
                algorithmIdentifier = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null),
            ),
        )
        val opaqueTbs = TbsCertificationRequest.fromAsn1(unknownKey)
        opaqueTbs.subjectName shouldBe Name.EMPTY
        opaqueTbs.attributes shouldBe emptyList()
        shouldThrowAny { opaqueTbs.publicKey }
        opaqueTbs.toAsn1() shouldBeSameInstanceAs unknownKey
    }

    "Alternative names compare their contents without encoding them" {
        val name: GeneralName = object : GeneralName {
            @SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
        }
        val first = AlternativeNames(listOf(name))
        val second = AlternativeNames(listOf(name))
        first shouldBe second
        first.hashCode() shouldBe second.hashCode()
        first shouldNotBe AlternativeNames(emptyList())
        shouldThrowAny { der.encodeToByteArray(first) }
    }

    "Only decoded values retain a source and other encodings leave it unchanged" {
        val ecSignature = EcdsaSignature.fromRS(BigInteger.ONE, BigInteger.TWO)
        ecSignature.sourceFormat shouldBe null
        val signatureModel = ecSignature.toAsn1()
        EcdsaSignature.fromAsn1Representation(signatureModel).toAsn1().rawBitString shouldBeSameInstanceAs signatureModel.rawBitString
        val rsaModel = RsaSignature(byteArrayOf(1, 2, 3)).toAsn1()
        RsaSignature.fromAsn1Representation(rsaModel).toAsn1().rawBitString shouldBeSameInstanceAs rsaModel.rawBitString

        val pss = RsaAlgorithm.Parameters.PssPadded(digest = Digest.SHA256)
        pss.sourceFormat shouldBe null
        val pssModel = pss.toAsn1()
        RsaAlgorithm.Parameters.PssPadded.fromAsn1Representation(pssModel).asn1Representation shouldBeSameInstanceAs pssModel

        val key = EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1,
            encodeCurve = true, encodePublicKey = true)
        key.sourceFormat shouldBe null
        val pkcs8 = key.toAsn1()
        val decoded = EcdsaPrivateKey.fromAsn1Representation(pkcs8)
        decoded.toAsn1() shouldBeSameInstanceAs pkcs8
        decoded shouldBe key
        val sec1 = key.asSEC1
        val fromSec1 = EcdsaPrivateKey.fromAsn1Representation(sec1)
        fromSec1.sourceRepresentation?.first shouldBe SEC1
        fromSec1.asSEC1 shouldBeSameInstanceAs sec1
        fromSec1 shouldBe key
        der.encodeToByteArray(fromSec1) shouldBe der.encodeToByteArray(key)
        fromSec1.attributes shouldBe null
        fromSec1.sourceRepresentation?.first shouldBe SEC1
        fromSec1.sourceRepresentation?.second shouldBeSameInstanceAs sec1
        decoded.sourceRepresentation?.second shouldBeSameInstanceAs pkcs8
        key.sourceRepresentation shouldBe null
        ecSignature.sourceRepresentation shouldBe null
        pss.sourceRepresentation shouldBe null

        val names = AlternativeNames.fromGeneralNames(emptyList())
        names.sourceRepresentation shouldBe null
        val namesModel = requireNotNull(names.asn1Representation)
        names.sourceRepresentation shouldBe null
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

    "PSS properties are independent of unsupported digest and MGF identifiers" {
        val unknown = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null)
        val original = RsaSsaPssParams(hashAlgorithm = unknown, maskGenAlgorithm = unknown, saltLength = 42)
        val decoded = RsaAlgorithm.Parameters.PssPadded.fromAsn1Representation(original)
        decoded.saltLength shouldBe 42u
        decoded.trailerField shouldBe 1
        shouldThrowAny { decoded.digest }
        shouldThrowAny { decoded.mgfAlgorithm }
        decoded.toAsn1() shouldBeSameInstanceAs original
    }

    "EC private scalar and retained source do not require a supported curve" {
        val unknownCurve = ObjectIdentifier("1.2.3.4")
        val original = Sec1EcPrivateKeyInfo(
            privateKey = ByteArray(32).apply { this[lastIndex] = 1 },
            parameters = unknownCurve, publicKey = null,
        )
        val decoded = EcdsaPrivateKey.fromAsn1Representation(original) as EcdsaPrivateKey.WithPublicKey
        decoded.privateKey shouldBe BigInteger.ONE
        decoded.encodeCurve shouldBe true
        decoded.encodePublicKey shouldBe false
        shouldThrowAny { decoded.publicKey }
        decoded.asSEC1 shouldBeSameInstanceAs original

        val pkcs8 = Pkcs8PrivateKeyInfo(
            privateKeyAlgorithm = X509AlgorithmIdentifier(KnownOIDs.ecPublicKey, der.encodeToTlv(unknownCurve)),
            privateKey = Asn1OctetString(der.encodeToByteArray(original)),
        )
        val fromPkcs8 = EcdsaPrivateKey.fromAsn1Representation(pkcs8) as EcdsaPrivateKey.WithPublicKey
        fromPkcs8.privateKey shouldBe BigInteger.ONE
        shouldThrowAny { fromPkcs8.curve }
        der.encodeToByteArray(fromPkcs8) shouldBe der.encodeToByteArray(pkcs8)
    }
}
