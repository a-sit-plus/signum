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
import at.asitplus.signum.dsl.DSL
import at.asitplus.signum.dsl.JCAProviderRef
import at.asitplus.signum.dsl.jvm
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
import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.os.JKSSigningKeyConfiguration
import at.asitplus.signum.supreme.os.JKSSigner
import at.asitplus.signum.supreme.os.JKSSignerConfiguration
import at.asitplus.signum.supreme.os.JavaKeyStoreOperationsProvider
import at.asitplus.signum.supreme.sign.SupremeEphemeralJvmSigner
import at.asitplus.signum.supreme.sign.SupremeJVMVerifier
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.Security
import java.nio.file.Files
import java.security.interfaces.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.PrivateKey as JcaPrivateKey
import java.security.PublicKey as JcaPublicKey
import java.security.Signature as JcaSignature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPrivateKeySpec
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
    "External ML-DSA provider round-trips through a persisted JKS and built-ins still dispatch" {
        isolatedScenario(ExternalCertificateScenarios::class.java, "mlDsaJksRoundTrip")
    }
}

internal object ExternalCertificateScenarios {
    @JvmStatic
    fun brainpoolCertificate() = runBlocking {
        installProviders()
        ServiceLoader.register<EcdsaPublicKeyDerivationProvider>(BrainpoolPrivateKeyProvider)
        ServiceLoader.register<JcaMappingProvider>(BrainpoolPrivateKeyProvider)
        // Generic import selects the wrapper first. Typed import continues to the typed mapper.
        ServiceLoader.register<JcaMappingProvider>(CertificateAddon)
        val pair = KeyPairGenerator.getInstance("EC", bc).apply {
            initialize(ECGenParameterSpec(brainpool.name))
        }.generateKeyPair()
        // Simulate a JCA key without an encoding so the DER fallback cannot supply the mapping.
        val jcaKey = object : ECPublicKey by (pair.public as ECPublicKey) {
            override fun getEncoded(): ByteArray? = null
            override fun getFormat(): String? = null
        }
        val publicKey: EcdsaPublicKey = jcaKey.toPublicKey()
        val jcaPrivateKey = BcPrivateKey(pair.private, publicKey).toJcaPrivateKey()
        (jcaPrivateKey === pair.private) shouldBe true
        val privateKey = jcaPrivateKey.toPrivateKey().shouldBeInstanceOf<BcPrivateKey>()
        privateKey.publicKey shouldBe publicKey
        verifyTypedBrainpoolPrivateKey(jcaPrivateKey as ECPrivateKey, publicKey)

        val certificate = verifySelfSigned(EcdsaAlgorithm(Digest.SHA256, brainpool), privateKey)
        (certificate.publicKey.shouldBeInstanceOf<EcdsaPublicKey>().curve === brainpool) shouldBe true
        brainpool.IDENTITY.isPointAtInfinity shouldBe true
        verifyNistDispatch()
    }

    @JvmStatic
    fun mlDsaCertificate() = runBlocking {
        installProviders()
        ServiceLoader.register<JcaMappingProvider>(CertificateAddon)
        val pair = KeyPairGenerator.getInstance(ML_DSA_44, bc).generateKeyPair()
        val decoded = PublicKey.fromAsn1(pair.public.encoded).shouldBeInstanceOf<MlDsaPublicKey>()
        // Rebuild the decoded key so certificate creation calls the add-on encoder.
        val certificate = verifySelfSigned(MlDsa44, BcPrivateKey(pair.private, MlDsaPublicKey(decoded.spki)))
        certificate.signatureAlgorithm shouldBe MlDsa44
        val _ = certificate.publicKey.shouldBeInstanceOf<MlDsaPublicKey>()
        val _ = certificate.signature.shouldBeInstanceOf<MlDsaSignature>()
        verifyNistDispatch()
    }

    @JvmStatic
    fun mlDsaJksRoundTrip() = runBlocking {
        installProviders()
        ServiceLoader.register<JcaMappingProvider>(CertificateAddon)
        ServiceLoader.register<JavaKeyStoreOperationsProvider>(CertificateAddon)
        val addedBouncyCastle = Security.addProvider(bc) != -1
        val storePath = Files.createTempFile("external-ml-dsa", ".jks").also { Files.delete(it) }
        try {
            val provider = JKSProvider {
                file {
                    file = storePath
                    password = "store-password".toCharArray()
                }
            }
            val alias = "external-ml-dsa"
            val keyPassword = "key-password".toCharArray()
            val created = provider.createSigningKey(alias) {
                mlDsa44 {}
                this.provider = JCAProviderRef.Of(bc.name)
                privateKeyPassword = keyPassword
            }
            val loaded = provider.getSignerForKey(alias) {
                this.provider = JCAProviderRef.Of(bc.name)
                privateKeyPassword = keyPassword
            }
            loaded.publicKey.asn1.toDer().contentEquals(created.publicKey.asn1.toDer()) shouldBe true
            loaded.alias shouldBe alias
            loaded.shouldBeInstanceOf<ExternalMlDsaJksSigner>()

            val message = byteArrayOf(3, 1, 4, 1, 5, 9)
            val signature = loaded.sign(message).signature
            MlDsa44.verifierFor(loaded.publicKey).verify(message, signature) shouldBe SignatureVerifier.Success

            provider.deleteSigningKey(alias)
            shouldThrow<NoSuchElementException> { provider.getSignerForKey(alias) }

            // The external operation declines EC, so Supreme's existing JKS operation and signer remain active.
            val builtinAlias = "builtin-ecdsa"
            val builtin = provider.createSigningKey(builtinAlias) {
                ec {}
                privateKeyPassword = keyPassword
            }
            builtin.shouldBeInstanceOf<JKSSigner.EC>()
            val builtinReloaded = provider.getSignerForKey(builtinAlias) { privateKeyPassword = keyPassword }
            builtinReloaded.shouldBeInstanceOf<JKSSigner.EC>()
            builtinReloaded.publicKey shouldBe builtin.publicKey
            builtinReloaded.makeVerifier().verify(message, builtinReloaded.sign(message).signature) shouldBe SignatureVerifier.Success
            provider.deleteSigningKey(builtinAlias)
            verifyNistDispatch()
        } finally {
            Files.deleteIfExists(storePath)
            if (addedBouncyCastle) Security.removeProvider(bc.name)
        }
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

    private fun verifyTypedBrainpoolPrivateKey(jcaKey: ECPrivateKey, publicKey: EcdsaPublicKey) {
        val privateKey: EcdsaPrivateKey.WithPublicKey = jcaKey.toPrivateKey()
        privateKey.publicKey shouldBe publicKey
        val roundTripped: ECPrivateKey = privateKey.toJcaPrivateKey()
        (roundTripped.s == jcaKey.s) shouldBe true
        EcdsaPrivateKey.WithPublicKey(privateKey.privateKey, brainpool).publicKey shouldBe publicKey

        val mismatchedScalar = if (privateKey.privateKey == BigInteger.ONE) BigInteger.fromInt(2) else BigInteger.ONE
        shouldThrow<IllegalArgumentException> { EcdsaPrivateKey.WithPublicKey(mismatchedScalar, publicKey) }
    }

    private suspend fun verifySelfSigned(algorithm: SignatureAlgorithm, key: BcPrivateKey): Certificate {
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
        val verifier = certificate.verifier()
        if (algorithm === MlDsa44) verifier.shouldBeInstanceOf<ExternalMlDsaJksVerifier>()
        else verifier.shouldBeInstanceOf<BcVerifier>()
        verifier.verify(certificate) shouldBe SignatureVerifier.Success
        return certificate
    }

    private suspend fun verifyNistDispatch() {
        val message = byteArrayOf(1, 2, 3)
        for (curve in ECCurve.entries) {
            val signer = Signer.Ephemeral { ec { this.curve = curve } }.shouldBeInstanceOf<SupremeEphemeralJvmSigner.EC>()
            val verifier = signer.makeVerifier().shouldBeInstanceOf<SupremeJVMVerifier.Ecdsa>()
            (signer.publicKey.curve === curve) shouldBe true
            signer.publicKey.toJcaPublicKey().toPublicKey().curve shouldBe curve
            verifier.verify(message, signer.sign(message).signature) shouldBe SignatureVerifier.Success
        }
    }
}

private val bc = BouncyCastleProvider()
private const val BRAINPOOL_NAME = "brainpoolP256r1"
private val brainpoolParameters = TeleTrusTNamedCurves.getByName(BRAINPOOL_NAME)
private const val ML_DSA_44 = "ML-DSA-44"
private val mlDsaIdentifier = X509AlgorithmIdentifier(ObjectIdentifier(NISTObjectIdentifiers.id_ml_dsa_44.id), null)

private fun java.math.BigInteger.toSignumInteger() = BigInteger.fromByteArray(toByteArray(), Sign.POSITIVE)

private val brainpool = object : ShortWeierstrassCurve {
    override val name = BRAINPOOL_NAME
    override val jwkName = name
    override val oid = ObjectIdentifier(TeleTrusTNamedCurves.getOID(name).id)
    private val parameters = brainpoolParameters

    override val modulus = parameters.curve.field.characteristic.toSignumInteger()
    override val order = parameters.n.toSignumInteger()
    override val cofactor = parameters.h.intValueExact()
    override val coordinateCreator = ModularBigInteger.creatorForModulo(modulus)
    override val scalarCreator by lazy { ModularBigInteger.creatorForModulo(order) }
    override val a = coordinateCreator.fromBigInteger(parameters.curve.a.toBigInteger().toSignumInteger())
    override val b = coordinateCreator.fromBigInteger(parameters.curve.b.toBigInteger().toSignumInteger())
    override val generator by lazy {
        val point = parameters.g.normalize()
        ShortWeierstrassCurve.Point.fromXY(this, point.affineXCoord.toBigInteger().toSignumInteger(), point.affineYCoord.toBigInteger().toSignumInteger())
    }
    override fun toString() = name
}
private val brainpoolIdentifier = X509AlgorithmIdentifier(EcdsaPublicKey.oid, brainpool.oid.encodeToTlv())

private fun ECKey.isBrainpool() = (params as? ECNamedCurveSpec)?.name == BRAINPOOL_NAME

private fun deriveBrainpoolPoint(privateKey: java.math.BigInteger): ShortWeierstrassCurve.Point.Normalized {
    val point = brainpoolParameters.g.multiply(privateKey).normalize()
    return ShortWeierstrassCurve.Point.fromXY(
        brainpool, point.affineXCoord.toBigInteger().toSignumInteger(), point.affineYCoord.toBigInteger().toSignumInteger(),
    )
}

private object BrainpoolPrivateKeyProvider : JcaMappingProvider, EcdsaPublicKeyDerivationProvider {
    override fun derivePublicPoint(curve: ShortWeierstrassCurve, privateKey: BigInteger) =
        if (curve === brainpool) deriveBrainpoolPoint(privateKey.toJavaBigInteger()) else null

    override fun jcaPrivateKeyToPrivateKey(privateKey: JcaPrivateKey): EcdsaPrivateKey.WithPublicKey? {
        if (privateKey !is ECPrivateKey || !privateKey.isBrainpool()) return null
        return EcdsaPrivateKey.WithPublicKey(privateKey.s.toSignumInteger(), brainpool)
    }

    override fun privateKeyToJcaPrivateKey(privateKey: PrivateKey): ECPrivateKey? {
        if (privateKey !is EcdsaPrivateKey.WithPublicKey || privateKey.curve !== brainpool) return null
        val params = with(brainpoolParameters) { ECNamedCurveSpec(BRAINPOOL_NAME, curve, g, n, h) }
        val spec = ECPrivateKeySpec(privateKey.privateKey.toJavaBigInteger(), params)
        return KeyFactory.getInstance("EC", bc).generatePrivate(spec) as ECPrivateKey
    }
}

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

private class MlDsaJksConfiguration : DSL.Data()
private val JKSSigningKeyConfiguration.mlDsa44 get() = _algSpecific.option("EXTERNAL_ML_DSA_44", ::MlDsaJksConfiguration)

private class ExternalMlDsaJksSigner(
    private val externalPrivateKey: JcaPrivateKey,
    override val publicKey: MlDsaPublicKey,
    provider: JCAProviderRef,
    override val alias: String,
    override val attestation: SelfAttestation,
) : SupremeEphemeralJvmSigner(externalPrivateKey, provider), JKSSigner {
    override val signatureAlgorithm: SignatureAlgorithm = MlDsa44
    override fun parseFromJca(bytes: ByteArray): Signature = MlDsaSignature(X509SignatureValue(bytes))

    @SecretExposure
    override suspend fun exportPrivateKey(): PrivateKey.WithPublicKey = BcPrivateKey(externalPrivateKey, publicKey)
}

private class ExternalMlDsaJksVerifier(
    algorithm: SignatureAlgorithm,
    key: PublicKey,
    provider: JCAProviderRef,
) : SupremeJVMVerifier(algorithm, key, provider) {
    override val signatureAlgorithm: SignatureAlgorithm = algorithm
    override val publicKey: PublicKey = key
}

private object CertificateAddon : InMemoryKeysProvider, SignatureVerifierProvider,
    Asn1PublicKeyFormatProvider, Asn1SignatureAlgorithmProvider, SignatureFormatProvider, JcaMappingProvider,
    JavaKeyStoreOperationsProvider {

    override fun createKeyPair(config: JKSSigningKeyConfiguration): Pair<SignatureAlgorithm, java.security.KeyPair>? =
        config.mlDsa44.v?.let { MlDsa44 to KeyPairGenerator.getInstance(ML_DSA_44, bc).generateKeyPair() }

    override fun getJKSSigner(
        jcaPrivateKey: JcaPrivateKey,
        alias: String,
        config: JKSSignerConfiguration,
        attestation: SelfAttestation,
    ): JKSSigner? {
        val key = attestation.certificate.publicKey as? MlDsaPublicKey ?: return null
        if (jcaPrivateKey.algorithm != ML_DSA_44) return null
        return ExternalMlDsaJksSigner(jcaPrivateKey, key, config.provider, alias, attestation)
    }

    override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration) = null

    override fun createSignerForKey(
        algorithm: SignatureAlgorithm, privateKey: PrivateKey.WithPublicKey, config: InMemorySignerConfiguration,
    ): BcSigner? {
        val key = privateKey as? BcPrivateKey ?: return null
        return jcaName(algorithm, key.publicKey)?.let { BcSigner(algorithm, key, it) }
    }

    override fun verifierFor(algorithm: SignatureAlgorithm, key: PublicKey, config: VerifierConfiguration): SignatureVerifier? {
        if (algorithm === MlDsa44 && key is MlDsaPublicKey) {
            return ExternalMlDsaJksVerifier(algorithm, key, config.jvm.v.provider)
        }
        val name = jcaName(algorithm, key) ?: return null
        val jcaKey = when (key) {
            is EcdsaPublicKey -> key.toJcaPublicKey()
            else -> KeyFactory.getInstance(ML_DSA_44, bc).generatePublic(X509EncodedKeySpec(key.asn1.toDer()))
        }
        return BcVerifier(algorithm, key, jcaKey, name)
    }

    override fun jcaPublicKeyToPublicKey(publicKey: JcaPublicKey): PublicKey? = when {
        publicKey.algorithm == ML_DSA_44 -> PublicKey.fromAsn1(publicKey.encoded)
        publicKey is ECPublicKey && publicKey.isBrainpool() ->
            EcdsaPublicKey.fromUncompressed(brainpool, publicKey.w.affineX.toByteArray(), publicKey.w.affineY.toByteArray())
        else -> null
    }

    override fun publicKeyToJcaPublicKey(publicKey: PublicKey): JcaPublicKey? = when (publicKey) {
        is MlDsaPublicKey -> KeyFactory.getInstance(ML_DSA_44, bc).generatePublic(X509EncodedKeySpec(publicKey.asn1.toDer()))
        is EcdsaPublicKey -> if (publicKey.curve === brainpool)
            KeyFactory.getInstance("EC", bc).generatePublic(X509EncodedKeySpec(publicKey.asn1.toDer())) as ECPublicKey
        else null
        else -> null
    }

    override fun jcaPrivateKeyToPrivateKey(privateKey: JcaPrivateKey): BcPrivateKey? {
        if (privateKey !is ECPrivateKey || !privateKey.isBrainpool()) return null
        return BcPrivateKey(privateKey, EcdsaPublicKey(deriveBrainpoolPoint(privateKey.s), false))
    }

    override fun privateKeyToJcaPrivateKey(privateKey: PrivateKey): ECPrivateKey? {
        val jcaKey = (privateKey as? BcPrivateKey)?.jcaKey as? ECPrivateKey ?: return null
        return jcaKey.takeIf { it.isBrainpool() }
    }

    override fun getJCASignatureInstance(
        algorithm: SignatureAlgorithm,
        jcaProviderRef: JCAProviderRef,
    ): JcaSignature? = if (algorithm !== MlDsa44) null else when (jcaProviderRef) {
        is JCAProviderRef.ByName -> JcaSignature.getInstance(ML_DSA_44, jcaProviderRef.provider)
        is at.asitplus.signum.dsl.JCAProviderRefO -> JcaSignature.getInstance(ML_DSA_44, jcaProviderRef.provider)
        JCAProviderRef.None -> JcaSignature.getInstance(ML_DSA_44, bc)
        else -> null
    }

    override fun parseJCASignatureBytes(algorithm: SignatureAlgorithm, sigBytes: ByteArray): Signature? =
        if (algorithm === MlDsa44) MlDsaSignature(X509SignatureValue(sigBytes)) else null

    override fun getJCASignatureBytes(signature: Signature): ByteArray? =
        (signature as? MlDsaSignature)?.asn1?.toRepresentation()?.rawBytes

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
