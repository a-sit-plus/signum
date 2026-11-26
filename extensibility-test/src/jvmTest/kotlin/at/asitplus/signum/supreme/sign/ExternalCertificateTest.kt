package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.io.UVarInt
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.installPkix
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey as JcaPrivateKey
import java.security.PublicKey as JcaPublicKey
import java.security.Signature as JcaSignature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import kotlin.time.Duration.Companion.hours
import kotlin.time.Instant

val ExternalCertificateTest by matrixSuite {
    "Brainpool self-signed certificate uses the add-on alongside Supreme NIST" {
        isolatedScenario(ExternalCertificateScenarios::class.java, "brainpoolCertificate")
    }
    "ML-DSA self-signed certificate uses the add-on alongside Supreme NIST" {
        isolatedScenario(ExternalCertificateScenarios::class.java, "mlDsaCertificate")
    }
}

internal object ExternalCertificateScenarios {
    @JvmStatic
    fun brainpoolCertificate() = runBlocking {
        installProviders()
        val pair = KeyPairGenerator.getInstance("EC", bc).apply {
            initialize(ECGenParameterSpec(brainpool.name))
        }.generateKeyPair()
        val certificate = verifySelfSigned(EcdsaAlgorithm(Digest.SHA256, brainpool), pair)
        (certificate.publicKey.shouldBeInstanceOf<EcdsaPublicKey>().curve === brainpool) shouldBe true
        verifyNistDispatch()
    }

    @JvmStatic
    fun mlDsaCertificate() = runBlocking {
        installProviders()
        val pair = KeyPairGenerator.getInstance(ML_DSA_44, bc).generateKeyPair()
        val certificate = verifySelfSigned(MlDsa44, pair)
        certificate.signatureAlgorithm shouldBe MlDsa44
        val _ = certificate.publicKey.shouldBeInstanceOf<MlDsaPublicKey>()
        val _ = certificate.signature.shouldBeInstanceOf<MlDsaSignature>()
        verifyNistDispatch()
    }

    private fun installProviders() {
        Signum.installSupreme()
        Signum.installPkix()
        ServiceLoader.register<InMemoryKeysProvider>(CertificateAddon)
        ServiceLoader.register<SignatureVerifierProvider>(CertificateAddon)
        ServiceLoader.register<Asn1PublicKeyFormatProvider>(CertificateAddon)
        ServiceLoader.register<Asn1SignatureAlgorithmProvider>(CertificateAddon)
        ServiceLoader.register<SignatureFormatProvider>(CertificateAddon)
    }

    private suspend fun verifySelfSigned(algorithm: SignatureAlgorithm, pair: KeyPair): Certificate {
        // Decoded keys retain their source SPKI. Rebuild the key so certificate creation calls the add-on encoder.
        val publicKey = when (val decoded = PublicKey.fromAsn1(pair.public.encoded)) {
            is EcdsaPublicKey -> EcdsaPublicKey(decoded.publicPoint, decoded.preferCompressedRepresentation)
            is MlDsaPublicKey -> MlDsaPublicKey(decoded.spki)
            else -> error("Expected a public key decoded by the certificate add-on")
        }
        val key = BcPrivateKey(pair.private, publicKey)
        val signer = algorithm.signerFor(key).shouldBeInstanceOf<BcSigner>()
        val name = Name.fromString("CN=Provider Test")
        val start = Instant.parse("2026-01-01T00:00:00Z")
        val tbs = TbsCertificate(
            serialNumber = BigInteger.ONE,
            validFrom = start,
            validUntil = start + 1.hours,
            signatureAlgorithm = algorithm,
            publicKey = signer.publicKey,
            issuerName = name,
            subjectName = name,
        )
        val certificate = Certificate.fromAsn1(signer.sign(tbs).asn1.toDer())
        certificate.tbsCertificate.issuerName shouldBe certificate.tbsCertificate.subjectName
        certificate.verifier().shouldBeInstanceOf<BcVerifier>().verify(certificate) shouldBe SignatureVerifier.Success
        return certificate
    }

    private suspend fun verifyNistDispatch() {
        val message = byteArrayOf(1, 2, 3)
        for (curve in ECCurve.entries) {
            val signer = Signer.Ephemeral { ec { this.curve = curve } }.shouldBeInstanceOf<SupremeEphemeralJvmSigner.EC>()
            val verifier = signer.makeVerifier().shouldBeInstanceOf<SupremeJVMVerifier.Ecdsa>()
            (signer.publicKey.curve === curve) shouldBe true
            verifier.verify(message, signer.sign(message).signature) shouldBe SignatureVerifier.Success
        }
    }
}

private val bc = BouncyCastleProvider()
private const val ML_DSA_44 = "ML-DSA-44"
private val mlDsaIdentifier = X509AlgorithmIdentifier(ObjectIdentifier(NISTObjectIdentifiers.id_ml_dsa_44.id), null)

private fun java.math.BigInteger.toSignumInteger() = BigInteger.fromByteArray(toByteArray(), Sign.POSITIVE)

private val brainpool = run {
    val name = "brainpoolP256r1"
    val parameters = TeleTrusTNamedCurves.getByName(name)
    val generator = parameters.g.normalize()
    CustomECCurve(
        name = name,
        jwkName = name,
        oid = ObjectIdentifier(TeleTrusTNamedCurves.getOID(name).id),
        modulus = parameters.curve.field.characteristic.toSignumInteger(),
        a = parameters.curve.a.toBigInteger().toSignumInteger(),
        b = parameters.curve.b.toBigInteger().toSignumInteger(),
        generatorX = generator.affineXCoord.toBigInteger().toSignumInteger(),
        generatorY = generator.affineYCoord.toBigInteger().toSignumInteger(),
        order = parameters.n.toSignumInteger(),
        cofactor = parameters.h.intValueExact(),
    )
}
private val brainpoolIdentifier = X509AlgorithmIdentifier(EcdsaPublicKey.oid, brainpool.oid.encodeToTlv())

private object MlDsa44 : SignatureAlgorithm {
    override val sourceRepresentation get() = SourceRepresentationStorage()
}

private class MlDsaPublicKey(val spki: SubjectPublicKeyInfo) : PublicKey {
    override val sourceRepresentation = SourceRepresentationStorage()
    override val additionalProperties = mutableMapOf<String, String>()
    override val didCodec: UVarInt get() = error("DID encoding is outside this fixture")
    override val didKeyBytes: ByteArray get() = error("DID encoding is outside this fixture")
}

private class MlDsaSignature(val wire: X509SignatureValue) : Signature {
    override val sourceRepresentation = SourceRepresentationStorage()
}

private class BcPrivateKey(val jcaKey: JcaPrivateKey, override val publicKey: PublicKey) : PrivateKey.WithPublicKey {
    override val sourceRepresentation = SourceRepresentationStorage()
}

private class BcSigner(
    override val signatureAlgorithm: SignatureAlgorithm,
    private val key: BcPrivateKey,
    private val jcaName: String,
) : Signer.WithExportableKey {
    override val publicKey get() = key.publicKey

    @SecretExposure
    override suspend fun exportPrivateKey() = key

    override suspend fun sign(data: SignatureInput) = SignatureResult.make {
        val bytes = JcaSignature.getInstance(jcaName, bc).run {
            initSign(key.jcaKey)
            updateFrom(data)
            sign()
        }
        if (signatureAlgorithm === MlDsa44) MlDsaSignature(X509SignatureValue(bytes))
        else EcdsaSignature.fromRawSignatureValue(bytes)
    }
}

private class BcVerifier(
    override val signatureAlgorithm: SignatureAlgorithm,
    override val publicKey: PublicKey,
    private val jcaKey: JcaPublicKey,
    private val jcaName: String,
) : SignatureVerifier {
    override suspend fun verify(data: SignatureInput, sig: Signature): SignatureVerifier.Success {
        val valid = JcaSignature.getInstance(jcaName, bc).run {
            initVerify(jcaKey)
            updateFrom(data)
            verify(sig.asn1.toRepresentation().rawBytes)
        }
        check(valid)
        return SignatureVerifier.Success
    }
}

private fun JcaSignature.updateFrom(input: SignatureInput) {
    require(input.format == null)
    input.data.forEach(::update)
}

private object CertificateAddon : InMemoryKeysProvider, SignatureVerifierProvider,
    Asn1PublicKeyFormatProvider, Asn1SignatureAlgorithmProvider, SignatureFormatProvider {

    override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration) = null

    override fun createSignerForKey(
        algorithm: SignatureAlgorithm, privateKey: PrivateKey.WithPublicKey, config: InMemorySignerConfiguration,
    ): BcSigner? {
        val key = privateKey as? BcPrivateKey ?: return null
        return jcaName(algorithm, key.publicKey)?.let { BcSigner(algorithm, key, it) }
    }

    override fun verifierFor(algorithm: SignatureAlgorithm, key: PublicKey, config: VerifierConfiguration): BcVerifier? {
        val name = jcaName(algorithm, key) ?: return null
        val jcaKey = KeyFactory.getInstance(if (key is EcdsaPublicKey) "EC" else ML_DSA_44, bc)
            .generatePublic(X509EncodedKeySpec(key.asn1.toDer()))
        return BcVerifier(algorithm, key, jcaKey, name)
    }

    private fun jcaName(algorithm: SignatureAlgorithm, key: PublicKey): String? = when {
        algorithm === MlDsa44 && key is MlDsaPublicKey -> ML_DSA_44
        algorithm is EcdsaAlgorithm && key is EcdsaPublicKey && key.curve === brainpool &&
            algorithm.digest == Digest.SHA256 && algorithm.matchesRequiredCurve(brainpool) -> "SHA256withECDSA"
        else -> null
    }

    override fun encodeToAsn1(value: PublicKey): SubjectPublicKeyInfo? = when (value) {
        is MlDsaPublicKey -> value.spki
        is EcdsaPublicKey -> if (value.curve === brainpool) {
            SubjectPublicKeyInfo(brainpoolIdentifier, Asn1BitString(value.toAnsiX963Encoded(useCompressed = false)))
        } else null
        else -> null
    }

    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): PublicKey? = when (publicKeyInfo.algorithmIdentifier) {
        mlDsaIdentifier -> MlDsaPublicKey(publicKeyInfo)
        brainpoolIdentifier -> EcdsaPublicKey.fromAnsiX963Bytes(brainpool, publicKeyInfo.subjectPublicKey.bitCarryingBytes)
        else -> null
    }

    override fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray) = null

    override fun encodeToAsn1(value: SignatureAlgorithm) = mlDsaIdentifier.takeIf { value === MlDsa44 }
    override fun decodeFromAsn1(algorithmIdentifier: X509AlgorithmIdentifier) = MlDsa44.takeIf { algorithmIdentifier == mlDsaIdentifier }
    override fun encodeToAsn1(value: Signature) = (value as? MlDsaSignature)?.wire
    override fun parseSignature(signatureAlgorithm: SignatureAlgorithm, signature: X509SignatureValue) =
        if (signatureAlgorithm === MlDsa44) MlDsaSignature(signature) else null
    override fun parseSignature(x509Algorithm: X509AlgorithmIdentifier, signature: X509SignatureValue) = null
}
