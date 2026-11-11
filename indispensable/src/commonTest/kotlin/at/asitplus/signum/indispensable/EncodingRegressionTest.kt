package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.matchers.shouldBe

val EncodingRegressionTest by matrixSuite {
    "iOS EC public key encoding is uncompressed regardless of compression preference" {
        val key = EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1).publicKey

        key.iosEncoded shouldBe key.toAnsiX963Encoded(useCompressed = false)
    }

    "RDN decoding preserves an opaque non-string attribute value" {
        val original = X500RelativeDistinguishedName(setOf(
            X500AttributeTypeAndValue(ObjectIdentifier("1.2.3.4"), Asn1OctetString(byteArrayOf(1))),
        ))

        RelativeDistinguishedName.fromAsn1(original).asn1.toRepresentation() shouldBe original
    }

    "Unknown signature algorithms, digests and MACs are distinct values" {
        val original = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null)

        setOf<Any>(
            SignatureAlgorithm.fromAsn1(original),
            Digest.fromAsn1(original),
            MessageAuthenticationCode.fromAsn1(original),
        ).size shouldBe 3
    }
}
