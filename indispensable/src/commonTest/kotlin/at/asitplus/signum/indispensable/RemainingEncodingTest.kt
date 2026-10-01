package at.asitplus.signum.indispensable

import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

val RemainingEncodingTest by matrixSuite {
    val der = DER { serializersModule = signumX509Serializers }

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
