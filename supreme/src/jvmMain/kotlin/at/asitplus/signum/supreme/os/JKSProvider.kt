package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.symmetric.RSAPadding
import at.asitplus.signum.indispensable.symmetric.SignatureAlgorithm
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
import at.asitplus.signum.supreme.UnsupportedCryptoException
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.dsl.REQUIRED
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
import kotlin.io.path.extension
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

class JKSSigningKeyConfiguration: PlatformSigningKeyConfigurationBase<JKSSignerConfiguration>() {
    /** The registered JCA provider to use. */
    var provider: String? = null
    /** The password with which to protect the private key. */
    var privateKeyPassword: CharArray? = null
    /** The lifetime of the private key's certificate. */
    var certificateValidityPeriod: Duration = (365*100).days
}

class JKSSignerConfiguration: PlatformSignerConfigurationBase(), JvmEphemeralSignerCompatibleConfiguration {
    /** The registered JCA provider to use. */
    override var provider: String? = null
    /** The password protecting the stored private key. */
    var privateKeyPassword: CharArray? = null
}

interface JKSSigner: Signer, Signer.WithAlias {
    class EC internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                   publicKey: CryptoPublicKey.EC, signatureAlgorithm: SignatureAlgorithm.ECDSA,
                                   override val alias: String)
        : EphemeralSigner.EC(config, privateKey, publicKey, signatureAlgorithm), JKSSigner

    class RSA internal constructor (config: JvmEphemeralSignerCompatibleConfiguration, privateKey: PrivateKey,
                                    publicKey: CryptoPublicKey.RSA, signatureAlgorithm: SignatureAlgorithm.RSA,
                                    override val alias: String)
        : EphemeralSigner.RSA(config, privateKey, publicKey, signatureAlgorithm), JKSSigner
}

private fun keystoreGetInstance(type: String, provider: String?) = when (provider) {
    null -> KeyStore.getInstance(type)
    else -> KeyStore.getInstance(type, provider)
}

/** Read handle, [requested][JKSAccessor.forReading] whenever the provider needs to perform a read operation.
 * This handle should serve as a shared lock on the underlying data to avoid data races. */
interface ReadAccessorBase: AutoCloseable {
    /** An ephemeral JCA [KeyStore] object which the provider may read from within the lifetime of the [ReadAccessorBase]. */
    val ks: KeyStore
}

/** Write handle, [requested][JKSAccessor.forWriting] whenever the provider needs to perform a write operation.
 * This handle should serve as an exclusive lock on the underlying data to avoid data races. */
abstract class WriteAccessorBase: AutoCloseable {
    /** An ephemeral JCA [KeyStore] object which the provider may read from and write to within the lifetime of the [WriteAccessorBase]. */
    abstract val ks: KeyStore
    /** If the provider has made changes to the keystore data, this is set to `true` before calling `.close()`. */
    protected var dirty = false; private set
    fun markAsDirty() { dirty = true }
}

/**
 * Interface for advanced domain-specific keystore access.
 * Allows for concurrency via [AutoCloseable] locking.
 *
 * @see forReading
 * @see forWriting
 */
interface JKSAccessor {
    /** Obtains an accessor handle for reading from the KeyStore.
     * The handle will be closed when the provider is done reading from the KeyStore. */
    fun forReading(): ReadAccessorBase
    /** Obtains an accessor handle for reading from and writing to the KeyStore.
     * The handle will be closed when the provider is done.
     * Check the [dirty][WriteAccessorBase.dirty] flag to see if changes were made to the data. */
    fun forWriting(): WriteAccessorBase
}

class JKSProvider internal constructor (private val access: JKSAccessor)
    : SigningProviderI<JKSSigner, JKSSignerConfiguration, JKSSigningKeyConfiguration> {

    override suspend fun createSigningKey(
        alias: String,
        configure: DSLConfigureFn<JKSSigningKeyConfiguration>
    ): KmmResult<JKSSigner> = catching {
        val config = DSL.resolve(::JKSSigningKeyConfiguration, configure)
        if (config.hardware.v?.backing == REQUIRED)
            throw UnsupportedCryptoException("Hardware storage is unsupported on the JVM")
        access.forWriting().use { ctx ->
            if (ctx.ks.containsAlias(alias))
                throw NoSuchElementException("Key with alias $alias already exists")

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
            alias)
        is CryptoPublicKey.RSA -> JKSSigner.RSA(config, privateKey as RSAPrivateKey, publicKey,
            SignatureAlgorithm.RSA(
                digest = if (config.rsa.v.digestSpecified) config.rsa.v.digest else Digest.SHA256,
                padding = if (config.rsa.v.paddingSpecified) config.rsa.v.padding else RSAPadding.PSS),
            alias)
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

    override suspend fun deleteSigningKey(alias: String) = catching {
        access.forWriting().use { ctx ->
            if (ctx.ks.containsAlias(alias)) {
                ctx.ks.deleteEntry(alias)
                ctx.markAsDirty()
            }
        }
    }

    companion object {
        operator fun invoke(configure: DSLConfigureFn<JKSProviderConfiguration> = null) = catching {
            makePlatformSigningProvider(DSL.resolve(::JKSProviderConfiguration, configure))
        }
        fun Ephemeral(type: String = KeyStore.getDefaultType(), provider: String? = null) = catching {
            JKSProvider(DummyJKSAccessor(keystoreGetInstance(type, provider).apply { load(null) }))
        }
    }
}

internal class DummyJKSAccessor(override val ks: KeyStore): JKSAccessor, ReadAccessorBase, WriteAccessorBase() {
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

/**
 * Specifies what the keystore should be backed by.
 *
 * Options are:
 * * [ephemeral] (the default)
 * * [file] (backed by a file on disk)
 * * [withBackingObject] (backed by the specified [KeyStore] object)
 * * [customAccessor] (backed by a custom [JKSAccessor] object)
 *
 * @see JKSSignerConfiguration
 */
class JKSProviderConfiguration internal constructor(): PlatformSigningProviderConfigurationBase() {
    sealed class KeyStoreConfiguration constructor(): DSL.Data()
    internal val _keystore = subclassOf<KeyStoreConfiguration>(default = EphemeralKeyStore())

    /** Constructs an ephemeral keystore. This is the default. */
    val ephemeral = _keystore.option(::EphemeralKeyStore)
    class EphemeralKeyStore internal constructor(): KeyStoreConfiguration() {
        /** The KeyStore type to use. */
        var storeType: String = KeyStore.getDefaultType()
        /** The JCA provider to use. Leave `null` to not care. */
        var provider: String? = null
    }

    /** Constructs a keystore that accesses the provided Java [KeyStore] object. Use `withBackingObject { store = ... }`. */
    val withBackingObject = _keystore.option(::KeyStoreObject)
    class KeyStoreObject internal constructor(): KeyStoreConfiguration() {
        /** The KeyStore object to use */
        lateinit var store: KeyStore
        /** The function to be called after the keystore has been modified. Can be `null`. */
        var flushCallback: ((KeyStore)->Unit)? = null
        override fun validate() {
            super.validate()
            require(this::store.isInitialized)
        }
    }

    /** Accesses a keystore on disk. Automatically flushes back to disk. Use `file { path = ... }.`*/
    val file = _keystore.option(::KeyStoreFile)
    class KeyStoreFile internal constructor(): KeyStoreConfiguration() {
        companion object {
            /** file-based keystore types per
             * [spec](https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html#keystore-types) */
            private fun typeForFile(file: Path) =
                when (file.extension.lowercase()) {
                    "jks" -> "jks"
                    "p12", "pfx" -> "pkcs12"
                    "jceks" -> "jceks"
                    else -> null
                }
        }
        private var _storeType: String? = null
        /** The KeyStore type to use. By default, auto-detects from the file extension, and falls back to [KeyStore.getDefaultType]. */
        var storeType get() = _storeType ?: typeForFile(file) ?: KeyStore.getDefaultType()
                      set(v) { _storeType = v }
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

    /** Accesses a keystore via a custom [JKSAccessor]. Use `keystoreCustomAccessor { accessor = ... }` */
    val customAccessor = _keystore.option(::KeyStoreAccessor)
    class KeyStoreAccessor internal constructor(): KeyStoreConfiguration() {
        /** A custom [JKSAccessor] to use. */
        lateinit var accessor: JKSAccessor

        override fun validate() {
            super.validate()
            require(this::accessor.isInitialized)
        }
    }
}

internal /*actual*/ fun makePlatformSigningProvider(config: JKSProviderConfiguration): JKSProvider =
    when (val opt = config._keystore.v) {
        is JKSProviderConfiguration.EphemeralKeyStore ->
            JKSProvider.Ephemeral(opt.storeType, opt.provider).getOrThrow()
        is JKSProviderConfiguration.KeyStoreObject ->
            JKSProvider(opt.flushCallback?.let { CallbackJKSAccessor(opt.store, it) } ?: DummyJKSAccessor(opt.store))
        is JKSProviderConfiguration.KeyStoreFile ->
            JKSProvider(JKSFileAccessor(opt))
        is JKSProviderConfiguration.KeyStoreAccessor ->
            JKSProvider(opt.accessor)
    }

internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProviderI<*,*,*> =
    throw UnsupportedOperationException("No default persistence mode is available on the JVM. Use JKSProvider {file {}} or similar. This will be natively available from the getPlatformSigningProvider {} DSL in a future release. (Blocked by KT-71036.)")
