package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.supreme.SecretExposure
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.os.PlatformSigningKeyConfigurationBase
import at.asitplus.signum.supreme.os.SignerConfiguration
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.signature
import at.asitplus.signum.supreme.succeed
import com.ionspin.kotlin.bignum.integer.Quadruple
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldNotBeIn
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNot
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.datetime.Clock
import kotlin.random.Random
import kotlin.time.Duration.Companion.days

interface SignatureTestSuite {
    val isPreHashed: Boolean
    fun configure(it: SigningKeyConfiguration)
    fun configure(it: SignerConfiguration)
}
data class ECDSATestSuite(val curve: ECCurve, val digest: Digest, override val isPreHashed: Boolean): SignatureTestSuite {
    override fun toString() = "ECDSA/$curve/$digest${if (isPreHashed) "/pre" else ""}"
    override fun configure(it: SigningKeyConfiguration) {
        it.ec {
            this.curve = this@ECDSATestSuite.curve
            this.digests = setOf(this@ECDSATestSuite.digest)
        }
        if (it is PlatformSigningKeyConfigurationBase<*>) {
            it.signer { this@ECDSATestSuite.configure(this@signer) }
        }
    }
    override fun configure(it: SignerConfiguration) {
        it.ec {
            this.digest = this@ECDSATestSuite.digest
        }
    }
}
data class RSATestSuite(val padding: RSAPadding, val digest: Digest, val keySize: Int, override val isPreHashed: Boolean): SignatureTestSuite {
    override fun toString() = "RSA/$digest/$padding/${keySize}bit${if (isPreHashed) "/pre" else ""}"
    override fun configure(it: SigningKeyConfiguration) {
        it.rsa {
            this.digests = setOf(this@RSATestSuite.digest)
            this.paddings = setOf(this@RSATestSuite.padding)
            this.bits = this@RSATestSuite.keySize
        }
        if (it is PlatformSigningKeyConfigurationBase<*>) {
            it.signer { this@RSATestSuite.configure(this@signer) }
        }
    }
    override fun configure(it: SignerConfiguration) {
        it.rsa {
            this.digest = this@RSATestSuite.digest
            this.padding = this@RSATestSuite.padding
        }
    }
}
object TestSuites {
    val ALL get() = ECDSA + RSA
    val ECDSA get() = sequence {
        ECCurve.entries.forEach { curve ->
            Digest.entries.forEach { digest ->
                yield(ECDSATestSuite(curve, digest, false))
                yield(ECDSATestSuite(curve, digest, true))
            }
        }
    }
    val RSA get() = sequence {
        RSAPadding.entries.forEach { padding ->
            Digest.entries.forEach { digest ->
                when {
                    digest == Digest.SHA512 && padding == RSAPadding.PSS
                        -> listOf(2048, 3072, 4096)
                    digest == Digest.SHA384 || digest == Digest.SHA512 || padding == RSAPadding.PSS
                        -> listOf(1024,2048,3072,4096)
                    else
                        -> listOf(512, 1024, 2048, 3072, 4096)
                }.forEach { keySize ->
                    yield(RSATestSuite(padding, digest, keySize, false))
                    yield(RSATestSuite(padding, digest, keySize, true))
                }
            }
        }
    }
}

@OptIn(SecretExposure::class)
class EphemeralSignerCommonTests : FreeSpec({
    "Functional" - {
        "RSA" - {
            withData(TestSuites.RSA) { (padding, digest, keySize, preHashed) ->
                val data = Random.Default.nextBytes(64)
                val signer: Signer
                val signature = try {
                    signer = Signer.Ephemeral {
                        rsa {
                            digests = setOf(digest); paddings = setOf(padding); bits = keySize
                        }
                    }.getOrThrow()
                    signer.sign(SignatureInput(data).let {
                        if (preHashed) it.convertTo(digest).getOrThrow() else it
                    }).signature
                } catch (x: UnsupportedOperationException) {
                    return@withData
                }
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.RSA>().let {
                    it.digest shouldBe digest
                    it.padding shouldBe padding
                }

                val secondSig = signer.exportPrivateKey()
                    .transform { signer.signatureAlgorithm.signerFor(it) }.getOrThrow().sign(data).signature

                val verifier = signer.makeVerifier().getOrThrow()
                verifier.verify(data, signature) should succeed
                verifier.verify(data, secondSig) should succeed
            }
        }
        "ECDSA" - {
            withData(TestSuites.ECDSA) { (crv, digest, preHashed) ->
                val signer =
                    Signer.Ephemeral { ec { curve = crv; digests = setOf(digest) } }.getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.ECDSA>().let {
                    it.digest shouldBe digest
                    it.requiredCurve shouldBeIn setOf(null, crv)
                }
                val data = Random.Default.nextBytes(64)
                val signature = signer.sign(SignatureInput(data).let {
                    if (preHashed) it.convertTo(digest).getOrThrow() else it
                }).signature


                val secondSig = signer.exportPrivateKey()
                    .transform { signer.signatureAlgorithm.signerFor(it)  }.getOrThrow().sign(data).signature

                val verifier = signer.makeVerifier().getOrThrow()
                verifier.verify(data, signature) should succeed
                verifier.verify(data, secondSig) should succeed
            }
        }
    }
    "Configuration" - {
        "ECDSA" - {
            "No digest specified (defaults to native)" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey { ec { this.curve = curve } }.getOrThrow()
                val signer = key.signer().getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.ECDSA>().digest shouldBe curve.nativeDigest

                key.exportPrivateKey().transform { signer.signatureAlgorithm.signerFor(it) } should succeed
            }
            "No digest specified, native disallowed, still succeeds" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey { ec { this.curve = curve; digests = Digest.entries.filter { it != curve.nativeDigest }.toSet() } }.getOrThrow()
                val signer = key.signer().getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.ECDSA>().digest shouldNotBeIn setOf(curve.nativeDigest, null)

                key.exportPrivateKey().transform { signer.signatureAlgorithm.signerFor(it) } should succeed
            }
            "All digests legal by default" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey { ec { this.curve = curve } }.getOrThrow()
                val nonNativeDigest = Random.of(Digest.entries.filter {it != curve.nativeDigest})
                val signer = key.signer { ec { digest = nonNativeDigest } }.getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.ECDSA>().digest shouldBe nonNativeDigest

                key.exportPrivateKey().transform { signer.signatureAlgorithm.signerFor(it) } should succeed
            }
            "Illegal digests should fail" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey { ec { this.curve = curve; digests = Digest.entries.filter {it != curve.nativeDigest}.toSet() } }.getOrThrow()
                key.signer { ec { digest = curve.nativeDigest } } shouldNot succeed
            }
            "Null digest should work as a default" {
                val key = EphemeralKey { ec { this.curve = Random.of(ECCurve.entries); digests = setOf<Digest?>(null) } }.getOrThrow()
                val signer = key.signer().getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.ECDSA>().digest shouldBe null

                key.exportPrivateKey().transform { signer.signatureAlgorithm.signerFor(it) } should succeed
            }
            "Null digest should work if explicitly specified" {
                val key = EphemeralKey { ec {} }.getOrThrow()
                val signer = key.signer { ec { digest = null } }.getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.ECDSA>().digest shouldBe null

                key.exportPrivateKey().transform { signer.signatureAlgorithm.signerFor(it) } should succeed
            }
        }
        "RSA" - {
            "No digest specified" {
                val key = EphemeralKey { rsa {} }.getOrThrow()
                val signer = key.signer().getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.RSA>()

                key.exportPrivateKey().transform { signer.signatureAlgorithm.signerFor(it) } should succeed
            }
        }
    }

    "Cert signing" - {
        "RSA" - {
            withData(TestSuites.RSA) { (padding, digest, keySize, preHashed) ->
                val data = Random.Default.nextBytes(64)
                val signer: Signer

                try {
                    signer = Signer.Ephemeral {
                        rsa {
                            digests = setOf(digest); paddings = setOf(padding); bits = keySize
                        }
                    }.getOrThrow()
                    signer.sign(SignatureInput(data).let {
                        if (preHashed) it.convertTo(digest).getOrThrow() else it
                    }).signature
                } catch (x: UnsupportedOperationException) {
                    return@withData
                }

                val csr = TbsCertificationRequest(
                    subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
                    publicKey = signer.publicKey,
                    attributes = listOf(
                        Pkcs10CertificationRequestAttribute(
                            // No OID is assigned for this; choose one!
                            KnownOIDs.id_sMIME,
                            // ↓↓↓ contains challenge ↓↓↓
                            Asn1String.UTF8("foo").encodeToTlv()
                        )
                    )
                )
                if(digest == Digest.SHA1 && padding== RSAPadding.PSS) return@withData
                val signedCSR = signer.sign(csr).getOrThrow()


                val verifier = signer.makeVerifier().getOrThrow()
                verifier.verify(signedCSR.tbsCsr.encodeToDer(), signedCSR.signature) should succeed


                val tbsCrt = TbsCertificate(
                    serialNumber = Random.nextBytes(16),
                    signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
                    issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("Foo")))),
                    validFrom = Asn1Time(
                        Clock.System.now()
                    ),
                    validUntil = Asn1Time(Clock.System.now() + 356.days),
                    subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
                    publicKey = signer.publicKey,
                    extensions = listOf(
                        X509CertificateExtension(
                            KnownOIDs.pkcs_12_OID,
                            critical = true,
                            Asn1OctetString(byteArrayOf())
                        )
                    )
                )
                val cert = signer.sign(tbsCrt).getOrThrow()

                verifier.verify(cert.tbsCertificate.encodeToDer(), cert.signature) should succeed

            }
        }

        "ECDSA" - {
            withData(TestSuites.ECDSA.filter { it.digest != Digest.SHA1 }) { (crv, digest, _) ->
                val signer =
                    Signer.Ephemeral { ec { curve = crv; digests = setOf(digest) } }.getOrThrow()
                signer.signatureAlgorithm.shouldBeInstanceOf<SignatureAlgorithm.ECDSA>().let {
                    it.digest shouldBe digest
                    it.requiredCurve shouldBeIn setOf(null, crv)
                }
                val csr = TbsCertificationRequest(
                    subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
                    publicKey = signer.publicKey,
                    attributes = listOf(
                        Pkcs10CertificationRequestAttribute(
                            // No OID is assigned for this; choose one!
                            KnownOIDs.id_sMIME,
                            // ↓↓↓ contains challenge ↓↓↓
                            Asn1String.UTF8("foo").encodeToTlv()
                        )
                    )
                )
                val signedCSR = signer.sign(csr).getOrThrow()


                val verifier = signer.makeVerifier().getOrThrow()
                verifier.verify(signedCSR.tbsCsr.encodeToDer(), signedCSR.signature) should succeed


                val tbsCrt = TbsCertificate(
                    serialNumber = Random.nextBytes(16),
                    signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
                    issuerName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("Foo")))),
                    validFrom = Asn1Time(
                        Clock.System.now()
                    ),
                    validUntil = Asn1Time(Clock.System.now() + 356.days),
                    subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
                    publicKey = signer.publicKey,
                    extensions = listOf(
                        X509CertificateExtension(
                            KnownOIDs.pkcs_12_OID,
                            critical = true,
                            Asn1PrimitiveOctetString(byteArrayOf())
                        )
                    )
                )
                val cert = signer.sign(tbsCrt).getOrThrow()

                verifier.verify(cert.tbsCertificate.encodeToDer(), cert.signature) should succeed
            }
        }
    }

})
