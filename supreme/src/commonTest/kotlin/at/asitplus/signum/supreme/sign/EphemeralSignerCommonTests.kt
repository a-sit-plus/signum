package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.*
import at.asitplus.awesn1.*
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.dsl.SigningKeyConfiguration
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.indispensable.sign.RSAAlgorithm.Padding as RSAPadding
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.supreme.InsecureRandom
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.dsl.PlatformSigningKeyConfigurationBase
import at.asitplus.signum.dsl.SignerConfiguration
import at.asitplus.signum.dsl.signer
import at.asitplus.signum.indispensable.integrity.verify
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.supreme.sign
import at.asitplus.signum.supreme.signature
import at.asitplus.signum.supreme.succeed
import at.asitplus.signum.supreme.verify
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.collections.shouldBeIn
import io.kotest.matchers.collections.shouldNotBeIn
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days

interface SignatureTestSuite {
    val isPreHashed: Boolean
    fun configure(it: SigningKeyConfiguration)
    fun configure(it: SignerConfiguration)
}

data class ECDSATestSuite(val curve: ECCurve, val digest: Digest, override val isPreHashed: Boolean) :
    SignatureTestSuite {
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

data class RSATestSuite(
    val padding: RSAPadding,
    val digest: Digest,
    val keySize: Int,
    override val isPreHashed: Boolean
) : SignatureTestSuite {
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
    val ECDSA
        get() = sequence {
            ECCurve.entries.forEach { curve ->
                Digest.entries.forEach { digest ->
                    yield(ECDSATestSuite(curve, digest, false))
                    yield(ECDSATestSuite(curve, digest, true))
                }
            }
        }
    val RSA
        get() = sequence {
            RSAPadding.entries.forEach { padding ->
                Digest.entries.forEach { digest ->
                    when {
                        digest == Digest.SHA512 && padding == RSAPadding.PSS
                            -> listOf(2048, 3072, 4096)

                        digest == Digest.SHA384 || digest == Digest.SHA512 || padding == RSAPadding.PSS
                            -> listOf(1024, 2048, 3072, 4096)

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
val EphemeralSignerCommonTests by matrixSuite {
    "Functional" - {
        "RSA" - {
            data(TestSuites.RSA) test { (padding, digest, keySize, preHashed) ->
                val data = Random.Default.nextBytes(64)
                val signer: Signer
                val signature = try {
                    signer = Signer.Ephemeral {
                        rsa {
                            digests = setOf(digest); paddings = setOf(padding); bits = keySize
                        }
                    }
                    signer.sign(SignatureInput(data).let {
                        if (preHashed) it.convertTo(digest).getOrThrow() else it
                    }).signature
                } catch (_: UnsupportedOperationException) {
                    return@test
                }
                signer.signatureAlgorithm.shouldBeInstanceOf<RSAAlgorithm>().let {
                    it.parameters shouldBe RSAAlgorithm.Parameters(padding, digest)
                }

                val secondSig = signer.exportPrivateKey()
                    .let { signer.signatureAlgorithm.signerFor(it) }
                    .sign(data).signature

                val verifier = signer.makeVerifier()
                verifier.verify(data, signature) should succeed
                verifier.verify(data, secondSig) should succeed
            }
        }
        "ECDSA" - {
            data(TestSuites.ECDSA) test { (crv, digest, preHashed) ->
                val data = Random.Default.nextBytes(64)
                val signer =
                    Signer.Ephemeral { ec { curve = crv; digests = setOf(digest) } }
                signer.signatureAlgorithm.shouldBeInstanceOf<ECDSAAlgorithm>().let {
                    it.digest shouldBe digest
                    it.requiredCurve shouldBeIn setOf(null, crv)
                }
                val signature = signer.sign(SignatureInput(data).let {
                    if (preHashed) it.convertTo(digest).getOrThrow() else it
                }).signature


                val secondSig = signer.exportPrivateKey()
                    .let { signer.signatureAlgorithm.signerFor(it) }
                    .sign(data).signature

                val verifier = signer.makeVerifier()
                verifier.verify(data, signature) should succeed
                verifier.verify(data, secondSig) should succeed
            }
        }
    }
    "Configuration" - {
        "ECDSA" - {
            "No digest specified (defaults to native)" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey { ec { this.curve = curve } }
                val signer = key.signer()
                signer.signatureAlgorithm.shouldBeInstanceOf<ECDSAAlgorithm>().digest shouldBe curve.nativeDigest

                shouldNotThrowAny { key.exportPrivateKey().let { signer.signatureAlgorithm.signerFor(it) } }
            }
            "No digest specified, native disallowed, still succeeds" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey {
                    ec {
                        this.curve = curve; digests = Digest.entries.filter { it != curve.nativeDigest }.toSet()
                    }
                }
                val signer = key.signer()
                signer.signatureAlgorithm.shouldBeInstanceOf<ECDSAAlgorithm>().digest shouldNotBeIn setOf(
                    curve.nativeDigest,
                    null
                )

                shouldNotThrowAny { key.exportPrivateKey().let { signer.signatureAlgorithm.signerFor(it) } }
            }
            "All digests legal by default" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey { ec { this.curve = curve } }
                val nonNativeDigest = Random.of(Digest.entries.filter { it != curve.nativeDigest })
                val signer = key.signer { ec { digest = nonNativeDigest } }
                signer.signatureAlgorithm.shouldBeInstanceOf<ECDSAAlgorithm>().digest shouldBe nonNativeDigest

                shouldNotThrowAny { key.exportPrivateKey().let { signer.signatureAlgorithm.signerFor(it) } }
            }
            "Illegal digests should fail" {
                val curve = Random.of(ECCurve.entries)
                val key = EphemeralKey {
                    ec {
                        this.curve = curve; digests = Digest.entries.filter { it != curve.nativeDigest }.toSet()
                    }
                }
                shouldThrowAny { key.signer { ec { digest = curve.nativeDigest } } }
            }
            "Null digest should work as a default" {
                val key = EphemeralKey {
                    ec {
                        this.curve = Random.of(ECCurve.entries); digests = setOf<Digest?>(null)
                    }
                }
                val signer = key.signer()
                signer.signatureAlgorithm.shouldBeInstanceOf<ECDSAAlgorithm>().digest shouldBe null

                shouldNotThrowAny { key.exportPrivateKey().let { signer.signatureAlgorithm.signerFor(it) } }
            }
            "Null digest should work if explicitly specified" {
                val key = EphemeralKey { ec {} }
                val signer = key.signer { ec { digest = null } }
                signer.signatureAlgorithm.shouldBeInstanceOf<ECDSAAlgorithm>().digest shouldBe null

                shouldNotThrowAny { key.exportPrivateKey().let { signer.signatureAlgorithm.signerFor(it) } }
            }
        }
        "RSA" - {
            "No digest specified" {
                val key = EphemeralKey { rsa {} }
                val signer = key.signer()
                signer.signatureAlgorithm.shouldBeInstanceOf<RSAAlgorithm>()

                shouldNotThrowAny { key.exportPrivateKey().let { signer.signatureAlgorithm.signerFor(it) } }
            }
        }
    }

    "Cert signing" - {
        "RSA" - {
            data(TestSuites.RSA) test { (padding, digest, keySize, preHashed) ->
                val data = Random.Default.nextBytes(64)
                val signer: Signer

                try {
                    signer = Signer.Ephemeral {
                        rsa {
                            digests = setOf(digest); paddings = setOf(padding); bits = keySize
                        }
                    }
                    signer.sign(SignatureInput(data).let {
                        if (preHashed) it.convertTo(digest).getOrThrow() else it
                    }).signature
                } catch (_: UnsupportedOperationException) {
                    return@test
                }

                val csr = TbsCertificationRequest(
                    subjectName = X500Name(X500AttributeTypeAndValue.CommonName("client")),
                    publicKey = signer.publicKey,
                    attributes = listOf(
                        CsrAttribute(
                            // No OID is assigned for this; choose one!
                            KnownOIDs.id_sMIME,
                            // ↓↓↓ contains challenge ↓↓↓
                            Asn1String.UTF8("foo").encodeToTlv()
                        )
                    )
                )
                if (digest == Digest.SHA1 && padding == RSAPadding.PSS) return@test
                val signedCSR = signer.sign(csr)


                val verifier = signer.makeVerifier()
                verifier.verify(signedCSR.tbsCsr, signedCSR.signature) should succeed


                val tbsCrt = TbsCertificate(
                    serialNumber = InsecureRandom.nextPositiveAsn1Integer(10),
                    signatureAlgorithm = signer.signatureAlgorithm,
                    issuerName = X500Name(X500AttributeTypeAndValue.CommonName("Foo")),
                    validFrom = Clock.System.now(),
                    validUntil = Clock.System.now() + 356.days,
                    subjectName = X500Name(X500AttributeTypeAndValue.CommonName("client")),
                    publicKey = signer.publicKey,
                    extensions = listOf(
                        CertificateExtension(
                            KnownOIDs.pkcs_12_OID,
                            critical = true,
                            Asn1OctetString(byteArrayOf())
                        )
                    )
                )
                val cert = signer.sign(tbsCrt)

                verifier.verify(cert.tbsCertificate, cert.signature) should succeed

            }
        }

        "ECDSA" - {
            data(TestSuites.ECDSA.filter { it.digest != Digest.SHA1 }) test { (crv, digest, _) ->
                val signer =
                    Signer.Ephemeral { ec { curve = crv; digests = setOf(digest) } }
                signer.signatureAlgorithm.shouldBeInstanceOf<ECDSAAlgorithm>().let {
                    it.digest shouldBe digest
                    it.requiredCurve shouldBeIn setOf(null, crv)
                }
                val csr = TbsCertificationRequest(
                    subjectName = X500Name(X500AttributeTypeAndValue.CommonName("client")),
                    publicKey = signer.publicKey,
                    attributes = listOf(
                        CsrAttribute(
                            // No OID is assigned for this; choose one!
                            KnownOIDs.id_sMIME,
                            // ↓↓↓ contains challenge ↓↓↓
                            Asn1String.UTF8("foo").encodeToTlv()
                        )
                    )
                )
                val signedCSR = signer.sign(csr)


                val verifier = signer.makeVerifier()
                verifier.verify(signedCSR.tbsCsr, signedCSR.signature) should succeed


                val tbsCrt = TbsCertificate(
                    serialNumber = InsecureRandom.nextPositiveAsn1Integer(10),
                    signatureAlgorithm = signer.signatureAlgorithm,
                    issuerName = X500Name(X500AttributeTypeAndValue.CommonName("Foo")),
                    validFrom = Clock.System.now(),
                    validUntil = Clock.System.now() + 356.days,
                    subjectName = X500Name(X500AttributeTypeAndValue.CommonName("client")),
                    publicKey = signer.publicKey,
                    extensions = listOf(
                        CertificateExtension(
                            KnownOIDs.pkcs_12_OID,
                            critical = true,
                            Asn1OctetString(byteArrayOf())
                        )
                    )
                )
                val cert = signer.sign(tbsCrt)

                verifier.verify(cert.tbsCertificate, cert.signature) should succeed
            }
        }
    }
}
