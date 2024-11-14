package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.pki.getContentSigner
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DLSequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.ContentSigner
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Security
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.*
import kotlin.math.absoluteValue
import kotlin.random.Random
import kotlin.random.nextInt
import kotlin.time.Duration.Companion.days

@OptIn(ExperimentalStdlibApi::class)
class SignatureCodecTest : FreeSpec({

    "EC" - {
        fun <T> Random.of(l: List<T>): T = l[this.nextInt(l.indices)]
        val curve = Random.of(listOf("secp256r1", "secp384r1", "secp521r1"))
        val digest = Random.of(listOf("SHA1", "SHA256", "SHA384", "SHA512"))
        val keys = KeyPairGenerator.getInstance("EC").also {
            it.initialize(ECGenParameterSpec(curve))
        }.generateKeyPair()
        val data = Random.nextBytes(256)
        val sig = Signature.getInstance("${digest}withECDSA").run {
            initSign(keys.private)
            update(data)
            sign()
        }

        CryptoSignature.EC.parseFromJca(sig).jcaSignatureBytes shouldBe sig
        CryptoSignature.parseFromJca(
            sig,
            SignatureAlgorithm.ECDSA(Digest.valueOf(digest), ECCurve.byJcaName(curve))
        ).jcaSignatureBytes shouldBe sig

        Signature.getInstance("${digest}withECDSAinP1363Format").run {
            initVerify(keys.public)
            update(data)
            verify(CryptoSignature.EC.parseFromJca(sig).encodeToDer())
        }
    }

    "RSA" - {
        Security.addProvider(BouncyCastleProvider())
        fun <T> Random.of(l: List<T>): T = l[this.nextInt(l.indices)]
        val digest = ("SHA256")
        val keys = KeyPairGenerator.getInstance("RSA").also {
        }.generateKeyPair()
        val data = Random.nextBytes(256)
        val sig = Signature.getInstance("${digest}withRSA").run {
            initSign(keys.private)
            update(data)
            sign()
        }

        CryptoSignature.RSAorHMAC.parseFromJca(sig).jcaSignatureBytes shouldBe sig
        CryptoSignature.parseFromJca(
            sig,
            SignatureAlgorithm.RSA(Digest.valueOf(digest), RSAPadding.PKCS1)
        ).jcaSignatureBytes shouldBe sig

        // create certificate with bouncycastle
        val notBeforeDate = Date.from(Instant.now())
        val notAfterDate = Date.from(Instant.now().plusSeconds(30.days.inWholeSeconds))
        val serialNumber: BigInteger = BigInteger.valueOf(Random.nextLong().absoluteValue)
        val commonName = "DefaultCryptoService"
        val issuer = X500Name("CN=$commonName")
        val builder = X509v3CertificateBuilder(
            /* issuer = */ issuer,
            /* serial = */ serialNumber,
            /* notBefore = */ notBeforeDate,
            /* notAfter = */ notAfterDate,
            /* subject = */ issuer,
            /* publicKeyInfo = */ SubjectPublicKeyInfo.getInstance(keys.public.encoded)
        )
        val signatureAlgorithm = X509SignatureAlgorithm.RS256
        val contentSigner: ContentSigner = signatureAlgorithm.getContentSigner(keys.private)
        val certificateHolder = builder.build(contentSigner)
        certificateHolder.signature
        val bcSig =
            (ASN1Sequence.fromByteArray(certificateHolder.encoded) as DLSequence).elementAt(2).toASN1Primitive().encoded
        CryptoSignature.RSAorHMAC.parseFromJca(certificateHolder.signature).encodeToDer() shouldBe bcSig
        CryptoSignature.parseFromJca(
            certificateHolder.signature,
            SignatureAlgorithm.RSA(Digest.valueOf(digest), RSAPadding.PKCS1)
        ).encodeToDer() shouldBe bcSig


    }


})

