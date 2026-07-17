package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.Asn1Null
import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.shouldSucceed
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.signature
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.engine.runBlocking
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import java.security.AlgorithmParameters
import java.security.Signature
import java.security.spec.PSSParameterSpec

@OptIn(SecretExposure::class)
val RsaSsaPssAgainstJvm by matrixSuite {

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
                }

                val privateKey = runBlocking { key.getOrThrow().exportPrivateKey().getOrThrow() }
                val signer = rsaInstance.signerFor(privateKey).getOrThrow()
                signer.signatureAlgorithm shouldBe rsaInstance

                val data = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

                val signumSigned = runBlocking { signer.sign(data).signature }

                val jvmParameters = AlgorithmParameters.getInstance("RSASSA-PSS").apply {
                    init(AlgorithmIdentifier.getInstance(rsaInstance.encodeToDer()).parameters.toASN1Primitive().encoded)
                }
                val jvmSigned = Signature.getInstance("RSASSA-PSS").run {
                    setParameter(jvmParameters.getParameterSpec(PSSParameterSpec::class.java))
                    initSign(privateKey.toJcaPrivateKey().getOrThrow())
                    update(data)
                    sign()
                }


                "Signum's verifier against JCA signed" {
                    rsaInstance.verifierFor(key.getOrThrow().publicKey).getOrThrow()
                        .verify(data, CryptoSignature.RSA.parseFromJca(jvmSigned)).shouldSucceed()
                }
                val jcaVerifier = Signature.getInstance("RSASSA-PSS").apply {
                    setParameter(jvmParameters.getParameterSpec(PSSParameterSpec::class.java))
                    initVerify(key.getOrThrow().publicKey.toJcaPublicKey().getOrThrow())
                    update(data)
                }

                "JCA verifier against Signum signed" {
                    jcaVerifier.verify(signumSigned.jcaSignatureBytes) shouldBe true
                }
            }
        }
    }
}