package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.fromJcaPublicKey
import at.asitplus.signum.indispensable.getJCASignatureInstance
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.parseFromJca
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.leaf
import at.asitplus.signum.indispensable.toJcaCertificate
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.sign.EphemeralSigner
import at.asitplus.signum.supreme.sign.JvmEphemeralSignerCompatibleConfiguration
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.SigningKeyConfiguration
import at.asitplus.signum.supreme.sign.getKPGInstance
import com.ionspin.kotlin.bignum.integer.base63.toJavaBigInteger
import kotlinx.datetime.Clock
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class JKSSigningKeyConfiguration: PlatformSigningKeyConfiguration<JKSSignerConfiguration>() {
    var provider: String? = null
    var privateKeyPassword: CharArray? = null
    var certificateValidityPeriod: Duration = 100.days
}

class JKSSignerConfiguration: PlatformSignerConfiguration(), JvmEphemeralSignerCompatibleConfiguration {
    override var provider: String? = null
    var privateKeyPassword: CharArray? = null
}

sealed interface JKSSigner: Signer, Signer.Attestable<SelfAttestation> {
    class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                   publicKey: CryptoPublicKey.EC, signatureAlgorithm: SignatureAlgorithm.ECDSA,
                                   certificate: X509Certificate)
        : EphemeralSigner.EC(config, privateKey, publicKey, signatureAlgorithm), JKSSigner {
        override val attestation = SelfAttestation(certificate)
    }

    class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                    publicKey: CryptoPublicKey.Rsa, signatureAlgorithm: SignatureAlgorithm.RSA,
                                    certificate: X509Certificate)
        : EphemeralSigner.RSA(config, privateKey, publicKey, signatureAlgorithm), JKSSigner {
        override val attestation = SelfAttestation(certificate)
    }
}

class JKSProvider(private val ks: KeyStore): SigningProviderI<JKSSigner, JKSSignerConfiguration, JKSSigningKeyConfiguration> {
    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<JKSSigningKeyConfiguration>
    ): KmmResult<JKSSigner> = catching {
        if (ks.containsAlias(alias))
            throw NoSuchElementException("Key with alias $alias already exists")
        val config = DSL.resolve(::JKSSigningKeyConfiguration, configure)

        val (jcaAlg,jcaSpec,certAlg) = when (val algSpec = config._algSpecific.v) {
            is SigningKeyConfiguration.RSAConfiguration ->
                Triple("RSA", RSAKeyGenParameterSpec(algSpec.bits, algSpec.publicExponent.toJavaBigInteger()), X509SignatureAlgorithm.RS256)
            is SigningKeyConfiguration.ECConfiguration ->
                Triple("EC", ECGenParameterSpec(algSpec.curve.jcaName), X509SignatureAlgorithm.ES256)
        }
        val keyPair = getKPGInstance(jcaAlg, config.provider).run {
            initialize(jcaSpec)
            generateKeyPair()
        }
        val cn = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(alias))))
        val publicKey = CryptoPublicKey.fromJcaPublicKey(keyPair.public).getOrThrow()
        val tbsCert = TbsCertificate(
            serialNumber = ByteArray(32).also { SecureRandom().nextBytes(it) },
            signatureAlgorithm = certAlg,
            issuerName = cn,
            subjectName = cn,
            validFrom = Asn1Time(Clock.System.now()),
            validUntil = Asn1Time(Clock.System.now() + config.certificateValidityPeriod),
            publicKey = publicKey
        )
        val cert = certAlg.getJCASignatureInstance(provider = config.provider, isAndroid = false).getOrThrow().run {
            initSign(keyPair.private)
            update(tbsCert.encodeToDer())
            sign()
        }.let { X509Certificate(tbsCert, certAlg, CryptoSignature.parseFromJca(it, certAlg)) }
        ks.setKeyEntry(alias, keyPair.private, config.privateKeyPassword,
                        arrayOf(cert.toJcaCertificate().getOrThrow()))

        return@catching getSigner(DSL.resolve(::JKSSignerConfiguration, config.signer.v), keyPair.private, cert)
    }

    private fun getSigner(
        config: JKSSignerConfiguration,
        privateKey: PrivateKey,
        certificate: X509Certificate
    ): JKSSigner = when (val publicKey = certificate.publicKey) {
        is CryptoPublicKey.EC -> JKSSigner.EC(config, privateKey as ECPrivateKey, publicKey,
            SignatureAlgorithm.ECDSA(
                digest = if (config.ec.v.digestSpecified) config.ec.v.digest else Digest.SHA256,
                requiredCurve = publicKey.curve),
            certificate)
        is CryptoPublicKey.Rsa -> JKSSigner.RSA(config, privateKey as RSAPrivateKey, publicKey,
            SignatureAlgorithm.RSA(
                digest = if (config.rsa.v.digestSpecified) config.rsa.v.digest else Digest.SHA256,
                padding = if (config.rsa.v.paddingSpecified) config.rsa.v.padding else RSAPadding.PSS),
            certificate)
    }

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<JKSSignerConfiguration>
    ): KmmResult<JKSSigner> = catching {
        val config = DSL.resolve(::JKSSignerConfiguration, configure)
        val privateKey = ks.getKey(alias, config.privateKeyPassword) as PrivateKey
        val certificateChain = ks.getCertificateChain(alias).map { X509Certificate.decodeFromDer(it.encoded) }
        return@catching getSigner(config, privateKey, certificateChain.leaf)
    }

    override suspend fun deleteSigningKey(alias: String) {
        if (ks.containsAlias(alias))
            ks.deleteEntry(alias)
    }

    companion object {
        fun Ephemeral(provider: String? = null) = JKSProvider(when (provider) {
            null -> KeyStore.getInstance(KeyStore.getDefaultType())
            else -> KeyStore.getInstance(KeyStore.getDefaultType(), provider)
        }.apply { load(null) })
    }
}
