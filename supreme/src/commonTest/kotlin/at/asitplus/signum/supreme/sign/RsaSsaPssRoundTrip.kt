package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.toAsn1
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.engine.runBlocking
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int

@OptIn(SecretExposure::class)
val RsaSsaPssRoundTripTest by matrixSuite {

    WellKnownDigest.entries.asData("Data Digest") - { dataDigest ->
        WellKnownDigest.entries.asData("Data Digest") - { mgfDigest ->

            mapOf(
                "from ASN.1" to RsaAlgorithm(
                    RsaAlgorithm.Parameters.PssPadded.fromAsn1(
                        RsaSsaPssParams(
                            hashAlgorithm = dataDigest.toAsn1(),
                            maskGenAlgorithm = RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(mgfDigest).toAsn1(),
                        )
                    )),
                "from Signum" to RsaAlgorithm(
                    RsaAlgorithm.Parameters.PssPadded(
                        digest = dataDigest,
                        mgfAlgorithm = RsaAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(
                            mgfDigest
                        )
                    )
                )
            ).asData("Parameters", nameFn = { i, (name, _) -> "$i: $name" }) - { (_, rsaInstance) ->

                val key = runBlocking {
                    Signer.Ephemeral {
                        rsa {
                            this.padding = RsaAlgorithm.Padding.PSS
                            this.digest = Digest.SHA256
                        }
                    }
                }

                val privateKey = runBlocking { key.exportPrivateKey() }
                val signer = rsaInstance.signerFor(privateKey)
                signer.signatureAlgorithm shouldBe rsaInstance

                compact("random payloads for RSA-PSS") - {
                    property(Arb.byteArray(Arb.int(1, 1000), Arb.byte()), iterations = 128) test { data ->
                        try {
                            val signumSigned = signer.sign(data).signature
                            rsaInstance.verifierFor(key.publicKey)
                                .verify(data, signumSigned) shouldBe SignatureVerifier.Success
                        } catch (_: UnsupportedCryptoException) { /* pass */ }
                    }
                }
            }
        }
    }
}
