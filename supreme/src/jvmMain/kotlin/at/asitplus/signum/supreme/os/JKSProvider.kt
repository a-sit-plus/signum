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
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.KeyStore
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.RSAPrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class JKSSigningKeyConfiguration: PlatformSigningKeyConfigurationBase<JKSSignerConfiguration>() {
    var provider: String? = null
    var privateKeyPassword: CharArray? = null
    var certificateValidityPeriod: Duration = 100.days
}

class JKSSignerConfiguration: PlatformSignerConfigurationBase(), JvmEphemeralSignerCompatibleConfiguration {
    override var provider: String? = null
    var privateKeyPassword: CharArray? = null
}

interface JKSSigner: Signer, Signer.Attestable<SelfAttestation>, Signer.WithAlias {
    class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                   publicKey: CryptoPublicKey.EC, signatureAlgorithm: SignatureAlgorithm.ECDSA,
                                   certificate: X509Certificate, override val alias: String)
        : EphemeralSigner.EC(config, privateKey, publicKey, signatureAlgorithm), JKSSigner {
        override val attestation = SelfAttestation(certificate)
    }

    class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                    publicKey: CryptoPublicKey.Rsa, signatureAlgorithm: SignatureAlgorithm.RSA,
                                    certificate: X509Certificate, override val alias: String)
        : EphemeralSigner.RSA(config, privateKey, publicKey, signatureAlgorithm), JKSSigner {
        override val attestation = SelfAttestation(certificate)
    }
}

private fun keystoreGetInstance(type: String, provider: String?) = when (provider) {
    null -> KeyStore.getInstance(type)
    else -> KeyStore.getInstance(type, provider)
}

sealed interface ReadAccessorBase: AutoCloseable {
    val ks: KeyStore
}

abstract class WriteAccessorBase: ReadAccessorBase {
    protected var dirty = false; private set
    fun markAsDirty() { dirty = true }
}

sealed interface JKSAccessor {
    fun forReading(): ReadAccessorBase
    fun forWriting(): WriteAccessorBase
}

class JKSProvider internal constructor (private val access: JKSAccessor)
    : SigningProviderI<JKSSigner, JKSSignerConfiguration, JKSSigningKeyConfiguration> {

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<JKSSigningKeyConfiguration>
    ): KmmResult<JKSSigner> = catching {
        access.forWriting().use { ctx ->
            if (ctx.ks.containsAlias(alias))
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
            val cert = certAlg.getJCASignatureInstance(provider = config.provider).getOrThrow().run {
                initSign(keyPair.private)
                update(tbsCert.encodeToDer())
                sign()
            }.let { X509Certificate(tbsCert, certAlg, CryptoSignature.parseFromJca(it, certAlg)) }
            ctx.ks.setKeyEntry(alias, keyPair.private, config.privateKeyPassword,
                            arrayOf(cert.toJcaCertificate().getOrThrow()))
            ctx.markAsDirty()

            getSigner(alias, DSL.resolve(::JKSSignerConfiguration, config.signer.v), keyPair.private, cert)
        }
    }

    private fun getSigner(
        alias: String,
        config: JKSSignerConfiguration,
        privateKey: PrivateKey,
        certificate: X509Certificate
    ): JKSSigner = when (val publicKey = certificate.publicKey) {
        is CryptoPublicKey.EC -> JKSSigner.EC(config, privateKey as ECPrivateKey, publicKey,
            SignatureAlgorithm.ECDSA(
                digest = if (config.ec.v.digestSpecified) config.ec.v.digest else Digest.SHA256,
                requiredCurve = publicKey.curve),
            certificate, alias)
        is CryptoPublicKey.Rsa -> JKSSigner.RSA(config, privateKey as RSAPrivateKey, publicKey,
            SignatureAlgorithm.RSA(
                digest = if (config.rsa.v.digestSpecified) config.rsa.v.digest else Digest.SHA256,
                padding = if (config.rsa.v.paddingSpecified) config.rsa.v.padding else RSAPadding.PSS),
            certificate, alias)
    }

    override suspend fun getSignerForKey(
        alias: String,
        configure: DSLConfigureFn<JKSSignerConfiguration>
    ): KmmResult<JKSSigner> = catching {
        access.forReading().use { ctx ->
            val config = DSL.resolve(::JKSSignerConfiguration, configure)
            val privateKey = ctx.ks.getKey(alias, config.privateKeyPassword) as PrivateKey
            val certificateChain = ctx.ks.getCertificateChain(alias).map { X509Certificate.decodeFromDer(it.encoded) }
            return@catching getSigner(alias, config, privateKey, certificateChain.leaf)
        }
    }

    override suspend fun deleteSigningKey(alias: String) {
        access.forWriting().use { ctx ->
            if (ctx.ks.containsAlias(alias)) {
                ctx.ks.deleteEntry(alias)
                ctx.markAsDirty()
            }
        }
    }

    companion object {
        operator fun invoke(configure: DSLConfigureFn<JKSProviderConfiguration> = null) =
            makePlatformSigningProvider(DSL.resolve(::JKSProviderConfiguration, configure))
        fun Ephemeral(type: String = KeyStore.getDefaultType(), provider: String? = null) =
            JKSProvider(DummyJKSAccessor(keystoreGetInstance(type, provider).apply { load(null) }))
    }
}

internal class DummyJKSAccessor(override val ks: KeyStore): JKSAccessor, WriteAccessorBase() {
    override fun forReading() = this
    override fun forWriting() = this
    override fun close() {}
}

internal class CallbackJKSAccessor(override val ks: KeyStore, private val callback: ((KeyStore)->Unit)?): ReadAccessorBase, JKSAccessor {
    inner class WriteAccessor: WriteAccessorBase() {
        override val ks: KeyStore get() = this@CallbackJKSAccessor.ks
        override fun close() { if (dirty) this@CallbackJKSAccessor.callback?.invoke(this@CallbackJKSAccessor.ks) }
    }

    override fun close() {}
    override fun forReading() = this
    override fun forWriting() = WriteAccessor()
}

internal class JKSFileAccessor(opt: JKSProviderConfiguration.KeyStoreFile) : JKSAccessor {
    val type = opt.storeType
    val file = opt.file
    val password = opt.password
    val readOnly = opt.readOnly
    val provider = opt.provider
    init {
        if (opt.createIfMissing && !readOnly) {
            try {
                FileChannel.open(file, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            } catch (_: java.nio.file.FileAlreadyExistsException) { null }
            ?.use { channel ->
                channel.lock().use {
                    channel.truncate(0L)
                    keystoreGetInstance(type, provider).apply { load(null) }
                        .store(Channels.newOutputStream(channel), password)
                }
            }
        }
    }
    inner class ReadAccessor: ReadAccessorBase {
        private val channel: FileChannel
        private val lock: FileLock
        override val ks: KeyStore
        init {
            channel = FileChannel.open(file, StandardOpenOption.READ)
            try {
                lock = channel.lock(0L, Long.MAX_VALUE, true)
                try {
                    ks = keystoreGetInstance(type, provider)
                        .apply { load(Channels.newInputStream(channel), password) }
                } catch (x: Exception) {
                    lock.close()
                    throw x
                }
            } catch (x: Exception) {
                channel.close()
                throw x
            }
        }

        override fun close() { try { lock.close(); } finally { channel.close() } }
    }
    override fun forReading() = ReadAccessor()

    inner class WriteAccessor: WriteAccessorBase() {
        private val channel: FileChannel
        private val lock: FileLock
        override val ks: KeyStore
        init {
            channel = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE)
            try {
                lock = channel.lock(0L, Long.MAX_VALUE, false)
                try {
                    ks = keystoreGetInstance(type, provider)
                        .apply { load(Channels.newInputStream(channel), password) }
                } catch (x: Exception) {
                    lock.close()
                    throw x
                }
            } catch (x: Exception) {
                channel.close()
                throw x
            }
        }

        override fun close() {
            try {
                if (dirty) {
                    channel.truncate(0L)
                    ks.store(Channels.newOutputStream(channel), password)
                }
            } finally {
                channel.use { channel ->
                    lock.close()
                }
            }
        }
    }
    override fun forWriting() = WriteAccessor()
}

class JKSProviderConfiguration internal constructor(): PlatformSigningProviderConfigurationBase() {
    sealed class KeyStoreConfiguration constructor(): DSL.Data()
    internal val _keystore = subclassOf<KeyStoreConfiguration>(default = EphemeralKeyStore())

    class EphemeralKeyStore internal constructor(): KeyStoreConfiguration() {
        /** The KeyStore type to use */
        var storeType: String = KeyStore.getDefaultType()
        /** The JCA provider to use. Leave `null` to not care. */
        var provider: String? = null
    }

    class KeyStoreObject internal constructor(): KeyStoreConfiguration() {
        /** The KeyStore object to use */
        lateinit var store: KeyStore
        /** The function to be called when the keystore is modified. Can be `null`. */
        var flushCallback: ((KeyStore)->Unit)? = null
        override fun validate() {
            super.validate()
            require(this::store.isInitialized)
        }
    }

    /**
     * Constructs a keystore from a java KeyStore object. Use `keystoreObject { store = ... }`.
     */
    val keystoreObject = _keystore.option(::KeyStoreObject)

    class KeyStoreFile internal constructor(): KeyStoreConfiguration() {
        /** The KeyStore type to use */
        var storeType = KeyStore.getDefaultType()
        /** The file to use */
        lateinit var file: Path
        /** The password to protect the keystore with */
        var password: CharArray? = null
        /** The JCA provider to use. Leave `null` to use any. */
        var provider: String? = null
        /** Whether to open the keystore file in read-only mode. Changes can be made, but will not be flushed to disk. Defaults to false. */
        var readOnly = false
        /** Whether to create the keystore file if missing. Defaults to true. Will be forced to false if `readOnly = true` is set. */
        var createIfMissing = true

        override fun validate() {
            super.validate()
            require(this::file.isInitialized)
        }
    }
    /**
     * Accesses a keystore on disk. Automatically flushes back to disk.
     */
    val keystoreFile = _keystore.option(::KeyStoreFile)
}

internal /*actual*/ fun makePlatformSigningProvider(config: JKSProviderConfiguration): KmmResult<JKSProvider> = catching {
    when (val opt = config._keystore.v) {
        is JKSProviderConfiguration.EphemeralKeyStore ->
            JKSProvider.Ephemeral(opt.storeType, opt.provider)
        is JKSProviderConfiguration.KeyStoreObject ->
            JKSProvider(opt.flushCallback?.let { CallbackJKSAccessor(opt.store, it) } ?: DummyJKSAccessor(opt.store))
        is JKSProviderConfiguration.KeyStoreFile ->
            JKSProvider(JKSFileAccessor(opt))
    }
}

/*actual typealias PlatformSigningProviderSigner = JKSSigner
actual typealias PlatformSigningProviderSignerConfiguration = JKSSignerConfiguration
actual typealias PlatformSigningProviderSigningKeyConfiguration = JKSSigningKeyConfiguration
actual typealias PlatformSigningProvider = JKSProvider
actual typealias PlatformSigningProviderConfiguration = JKSProviderConfiguration*/
