package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.crypto.RsaSsaPssParams
import at.asitplus.shouldSucceed
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.verifierFor
import at.asitplus.signum.indispensable.integrity.verify
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSASignature
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
                "from ASN.1" to RSAAlgorithm(
                    RSAAlgorithm.Parameters.PssPadded(
                    RsaSsaPssParams(
                        hashAlgorithm = dataDigest.asn1Representation,
                        maskGenAlgorithm = RSAAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(mgfDigest).asn1Representation,
                    )
                )),
                "from Signum" to RSAAlgorithm(
                    RSAAlgorithm.Parameters.PssPadded(
                        digest = dataDigest,
                        mgfAlgorithm = RSAAlgorithm.Parameters.PssPadded.MaskGenerationFunction.Pkcs1Mgf1(
                            mgfDigest
                        )
                    )
                )
            ).asData("Parameters", nameFn = { i, (name, _) -> "$i: $name" }) - { (_, rsaInstance) ->


                val key = runBlocking {
                    Signer.Ephemeral {
                        rsa {
                            this.padding = RSAAlgorithm.Padding.PSS
                        }
                    }
                }

                val privateKey = runBlocking { key.exportPrivateKey() }
                val signer = rsaInstance.signerFor(privateKey)
                signer.signatureAlgorithm shouldBe rsaInstance

                val data = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)

                val signumSigned = runBlocking { signer.sign(data).signature }

                val jvmParameters = AlgorithmParameters.getInstance("RSASSA-PSS").apply {
                    init(AlgorithmIdentifier.getInstance(rsaInstance.encodeToDer()).parameters.toASN1Primitive().encoded)
                }
                val jvmSigned = Signature.getInstance("RSASSA-PSS").run {
                    setParameter(jvmParameters.getParameterSpec(PSSParameterSpec::class.java))
                    initSign(privateKey.toJcaPrivateKey())
                    update(data)
                    sign()
                }


                "Signum's verifier against JCA signed" {
                    rsaInstance.verifierFor(key.publicKey)
                        .verify(data, RSASignature.parseFromJca(jvmSigned)).shouldSucceed()
                }
                val jcaVerifier = Signature.getInstance("RSASSA-PSS").apply {
                    setParameter(jvmParameters.getParameterSpec(PSSParameterSpec::class.java))
                    initVerify(key.publicKey.toJcaPublicKey())
                    update(data)
                }

                "JCA verifier against Signum signed" {
                    jcaVerifier.verify(signumSigned.jcaSignatureBytes) shouldBe true
                }
            }
        }
    }
}