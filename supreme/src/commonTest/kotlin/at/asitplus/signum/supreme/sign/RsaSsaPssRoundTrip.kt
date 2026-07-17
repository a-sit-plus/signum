package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.shouldSucceed
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.engine.runBlocking
import io.kotest.matchers.shouldBe
import io.kotest.property.Arb
import io.kotest.property.arbitrary.byte
import io.kotest.property.arbitrary.byteArray
import io.kotest.property.arbitrary.int

@OptIn(SecretExposure::class)
val RsaSsaPssRoundTripTest by matrixSuite {

    Digest.entries.asData("Data Digest") - { dataDigest ->
        Digest.entries.asData("Data Digest") - { mgfDigest ->

            mapOf(
                "from ASN.1" to SignatureAlgorithm.RSA(
                    SignatureAlgorithm.RSA.Parameters.PssPadded(
                        RsaSsaPssParams(
                            hashAlgorithm = X509AlgorithmIdentifier(
                                dataDigest.oid,
                                listOf(Asn1Null),
                            ),
                            maskGenAlgorithm = X509AlgorithmIdentifier(
                                SignatureAlgorithm.RSA.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1.oid,
                                listOf(
                                    Asn1.Sequence {
                                        +mgfDigest.oid
                                        +Asn1Null
                                    }
                                ),
                            ),
                        )
                    )),
                "from Signum" to SignatureAlgorithm.RSA(
                    SignatureAlgorithm.RSA.Parameters.PssPadded(
                        digest = dataDigest,
                        mgfAlgorithm = SignatureAlgorithm.RSA.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(
                            mgfDigest
                        )
                    )
                )).asData("Parameters", nameFn = { i, (name, _) -> "$i: $name" }) - { (_, rsaInstance) ->


                val key = runBlocking {
                    EphemeralKey {
                        rsa {
                            this.paddings = setOf(SignatureAlgorithm.RSA.Padding.PSS)
                            this.digests = Digest.entries.toSet()
                        }
                    }
                }.getOrThrow()

                val privateKey = runBlocking { key.exportPrivateKey().getOrThrow() }
                val signer = rsaInstance.signerFor(privateKey).getOrThrow()
                signer.signatureAlgorithm shouldBe rsaInstance

                compact("random payloads for RSA-PSS") - {
                    property(Arb.byteArray(Arb.int(1, 1000), Arb.byte()), iterations = 128) test { data ->
                        try {
                            val signumSigned = signer.sign(data).signature
                            rsaInstance.verifierFor(key.publicKey).getOrThrow()
                                .verify(data, signumSigned).shouldSucceed()
                        } catch (_: UnsupportedCryptoException) { /* pass */ }
                    }
                }
            }
        }
    }
}