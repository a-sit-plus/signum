package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionPadding
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm

/**
 * Global registry of built-in and third-party algorithms.
 *
 * Third-party code can register custom algorithms to participate in lookups and enumeration.
 */
object AlgorithmRegistry {
    private val signatureMappingsBacking = linkedMapOf<String, LinkedHashMap<SignatureMappingKey, Any>>()
    private val exactSignatureMappingsBacking = linkedMapOf<String, LinkedHashMap<SignatureAlgorithm, Any>>()
    private val macMappingsBacking = linkedMapOf<String, LinkedHashMap<MacMappingKey, Any>>()
    private val exactMacMappingsBacking = linkedMapOf<String, LinkedHashMap<MessageAuthenticationCode, Any>>()
    private val symmetricMappingsBacking = linkedMapOf<String, LinkedHashMap<SymmetricMappingKey, Any>>()
    private val exactSymmetricMappingsBacking =
        linkedMapOf<String, LinkedHashMap<SymmetricEncryptionAlgorithm<*, *, *>, Any>>()
    private val asymmetricMappingsBacking = linkedMapOf<String, LinkedHashMap<AsymmetricEncryptionMappingKey, Any>>()
    private val exactAsymmetricMappingsBacking =
        linkedMapOf<String, LinkedHashMap<AsymmetricEncryptionAlgorithm, Any>>()
    private val x509ToSignatureBacking = linkedMapOf<X509SignatureKey, SignatureAlgorithm>()
    private val signatureToX509Backing = linkedMapOf<SignatureAlgorithm, SignatureAlgorithmIdentifier>()
    private val signatureKeyToX509Backing = linkedMapOf<SignatureMappingKey, SignatureAlgorithmIdentifier>()

    private val signatureAlgorithmsBacking = linkedSetOf<SignatureAlgorithm>()
    private val dataIntegrityAlgorithmsBacking = linkedSetOf<DataIntegrityAlgorithm>()
    private val messageAuthenticationCodesBacking = linkedSetOf<MessageAuthenticationCode>()
    private val symmetricEncryptionAlgorithmsBacking = linkedSetOf<SymmetricEncryptionAlgorithm<*, *, *>>()
    private val signatureRsaPaddingsBacking = linkedSetOf<RsaSignaturePadding>()
    private val asymmetricRsaPaddingsBacking = linkedSetOf<RsaEncryptionPadding>()
    private val asymmetricEncryptionAlgorithmsBacking = linkedSetOf<AsymmetricEncryptionAlgorithm>()

    private var installingBuiltIns = false
    private val builtInsInitialized by lazy {
        installingBuiltIns = true
        try {
            registerInternalBuiltIns()
        } finally {
            installingBuiltIns = false
        }
    }

    private fun ensureBuiltIns() {
        if (!installingBuiltIns) {
            builtInsInitialized
        }
    }

    val signatureAlgorithms: List<SignatureAlgorithm>
        get() {
            ensureBuiltIns()
            return signatureAlgorithmsBacking.toList()
        }
    val dataIntegrityAlgorithms: List<DataIntegrityAlgorithm>
        get() {
            ensureBuiltIns()
            return dataIntegrityAlgorithmsBacking.toList()
        }
    val messageAuthenticationCodes: List<MessageAuthenticationCode>
        get() {
            ensureBuiltIns()
            return messageAuthenticationCodesBacking.toList()
        }
    val symmetricEncryptionAlgorithms: List<SymmetricEncryptionAlgorithm<*, *, *>>
        get() {
            ensureBuiltIns()
            return symmetricEncryptionAlgorithmsBacking.toList()
        }
    val signatureRsaPaddings: List<RsaSignaturePadding>
        get() {
            ensureBuiltIns()
            return signatureRsaPaddingsBacking.toList()
        }
    val asymmetricRsaPaddings: List<RsaEncryptionPadding>
        get() {
            ensureBuiltIns()
            return asymmetricRsaPaddingsBacking.toList()
        }
    val asymmetricEncryptionAlgorithms: List<AsymmetricEncryptionAlgorithm>
        get() {
            ensureBuiltIns()
            return asymmetricEncryptionAlgorithmsBacking.toList()
        }

    fun <T : SignatureAlgorithm> registerSignatureAlgorithm(algorithm: T) = registerSignatureAlgorithm(algorithm, true)
    internal fun <T : SignatureAlgorithm> registerSignatureAlgorithm(algorithm: T, ensure: Boolean): T =
        algorithm.also {
            if (ensure) ensureBuiltIns()
            signatureAlgorithmsBacking += it
            dataIntegrityAlgorithmsBacking += it
        }

    fun <T : MessageAuthenticationCode> registerMessageAuthenticationCode(algorithm: T) =
        registerMessageAuthenticationCode(algorithm, true)

    internal fun <T : MessageAuthenticationCode> registerMessageAuthenticationCode(algorithm: T, ensure: Boolean): T =
        algorithm.also {
            if (ensure) ensureBuiltIns()
            messageAuthenticationCodesBacking += it
            dataIntegrityAlgorithmsBacking += it
        }

    fun <T : SymmetricEncryptionAlgorithm<*, *, *>> registerSymmetricEncryptionAlgorithm(algorithm: T): T =
        registerSymmetricEncryptionAlgorithm(algorithm, ensure = true)

    internal fun <T : SymmetricEncryptionAlgorithm<*, *, *>> registerSymmetricEncryptionAlgorithm(
        algorithm: T,
        ensure: Boolean
    ): T =
        algorithm.also {
            if (ensure) ensureBuiltIns()
            symmetricEncryptionAlgorithmsBacking += it
        }

    fun <T : RsaSignaturePadding> registerSignatureRsaPadding(padding: T) = registerSignatureRsaPadding(padding, true)
    internal fun <T : RsaSignaturePadding> registerSignatureRsaPadding(padding: T, ensure: Boolean): T = padding.also {
        if (ensure) ensureBuiltIns()
        signatureRsaPaddingsBacking += it
    }

    fun <T : RsaEncryptionPadding> registerAsymmetricRsaPadding(padding: T) =
        registerAsymmetricRsaPadding(padding, true)

    internal fun <T : RsaEncryptionPadding> registerAsymmetricRsaPadding(padding: T, ensure: Boolean): T =
        padding.also {
            if (ensure) ensureBuiltIns()
            asymmetricRsaPaddingsBacking += it
        }

    fun <T : AsymmetricEncryptionAlgorithm> registerAsymmetricEncryptionAlgorithm(algorithm: T): T =
        registerAsymmetricEncryptionAlgorithm(algorithm, ensure = true)

    internal fun <T : AsymmetricEncryptionAlgorithm> registerAsymmetricEncryptionAlgorithm(
        algorithm: T,
        ensure: Boolean
    ): T = algorithm.also {
        if (ensure) ensureBuiltIns()
        asymmetricEncryptionAlgorithmsBacking += it
    }

    fun <T : Any> registerSignatureMapping(namespace: String, key: SignatureMappingKey, target: T) =
        registerSignatureMapping(namespace, key, target, true)

    internal fun <T : Any> registerSignatureMapping(
        namespace: String,
        key: SignatureMappingKey,
        target: T,
        ensure: Boolean
    ): T = target.also {
        if (ensure) ensureBuiltIns()
        signatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerSignatureMapping(namespace: String, algorithm: SignatureAlgorithm, target: T): T =
        target.also {
            ensureBuiltIns()
            exactSignatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
            algorithm.signatureMappingKeyOrNull()?.let { key ->
                signatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                    if (!contains(key)) put(key, it)
                }
            }
        }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findSignatureMapping(namespace: String, algorithm: SignatureAlgorithm): T? =
        ensureBuiltIns().let {
            (exactSignatureMappingsBacking[namespace]?.get(algorithm) as? T)
                ?: algorithm.signatureMappingKeyOrNull()?.let { key ->
                    (signatureMappingsBacking[namespace]?.get(key) as? T)
                        ?: key.genericCurveFallback()?.let { signatureMappingsBacking[namespace]?.get(it) as? T }
                }
        }

    fun <T : Any> registerMacMapping(namespace: String, key: MacMappingKey, target: T): T = target.also {
        ensureBuiltIns()
        macMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerMacMapping(namespace: String, algorithm: MessageAuthenticationCode, target: T): T =
        target.also {
            ensureBuiltIns()
            exactMacMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
            algorithm.macMappingKeyOrNull()?.let { key ->
                macMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                    if (!contains(key)) put(key, it)
                }
            }
        }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findMacMapping(namespace: String, algorithm: MessageAuthenticationCode): T? =
        ensureBuiltIns().let {
            (exactMacMappingsBacking[namespace]?.get(algorithm) as? T)
                ?: algorithm.macMappingKeyOrNull()?.let { macMappingsBacking[namespace]?.get(it) as? T }
        }

    fun <T : Any> registerSymmetricMapping(namespace: String, key: SymmetricMappingKey, target: T): T = target.also {
        ensureBuiltIns()
        symmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerSymmetricMapping(
        namespace: String,
        algorithm: SymmetricEncryptionAlgorithm<*, *, *>,
        target: T
    ): T = target.also {
        ensureBuiltIns()
        exactSymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
        algorithm.symmetricMappingKeyOrNull()?.let { key ->
            symmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                if (!contains(key)) put(key, it)
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findSymmetricMapping(namespace: String, algorithm: SymmetricEncryptionAlgorithm<*, *, *>): T? =
        ensureBuiltIns().let {
            (exactSymmetricMappingsBacking[namespace]?.get(algorithm) as? T)
                ?: algorithm.symmetricMappingKeyOrNull()?.let { symmetricMappingsBacking[namespace]?.get(it) as? T }
        }

    fun <T : Any> registerAsymmetricMapping(namespace: String, key: AsymmetricEncryptionMappingKey, target: T) =
        registerAsymmetricMapping(namespace, key, target, true)

    internal fun <T : Any> registerAsymmetricMapping(
        namespace: String,
        key: AsymmetricEncryptionMappingKey,
        target: T,
        ensure: Boolean
    ): T =
        target.also {
            if (ensure) ensureBuiltIns()
            asymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
        }

    fun <T : Any> registerAsymmetricMapping(namespace: String, algorithm: AsymmetricEncryptionAlgorithm, target: T): T =
        target.also {
            ensureBuiltIns()
            exactAsymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
            algorithm.asymmetricEncryptionMappingKeyOrNull()?.let { key ->
                asymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                    if (!contains(key)) put(key, it)
                }
            }
        }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findAsymmetricMapping(namespace: String, algorithm: AsymmetricEncryptionAlgorithm): T? =
        ensureBuiltIns().let {
            (exactAsymmetricMappingsBacking[namespace]?.get(algorithm) as? T)
                ?: algorithm.asymmetricEncryptionMappingKeyOrNull()
                    ?.let { asymmetricMappingsBacking[namespace]?.get(it) as? T }
        }

    fun registerX509SignatureMapping(
        raw: SignatureAlgorithmIdentifier,
        algorithm: SignatureAlgorithm
    ): SignatureAlgorithm = registerX509SignatureMapping(raw, algorithm, true)

    internal fun registerX509SignatureMapping(
        raw: SignatureAlgorithmIdentifier,
        algorithm: SignatureAlgorithm,
        ensure: Boolean,
    ): SignatureAlgorithm = algorithm.also {
        if (ensure) ensureBuiltIns()
        val rawKey = X509SignatureKey(raw.oid, raw.parameters)
        x509ToSignatureBacking[rawKey] = it
        signatureToX509Backing[it] = raw
        it.signatureMappingKeyOrNull()?.let { signatureKeyToX509Backing[it] = raw }
    }

    fun findSignatureAlgorithm(raw: SignatureAlgorithmIdentifier): SignatureAlgorithm? =
        ensureBuiltIns().let {
            x509ToSignatureBacking[X509SignatureKey(raw.oid, raw.parameters)]
        }

    fun findX509SignatureIdentifier(algorithm: SignatureAlgorithm): SignatureAlgorithmIdentifier? =
        ensureBuiltIns().let {
            signatureToX509Backing[algorithm]
                ?: algorithm.signatureMappingKeyOrNull()?.let { key ->
                    signatureKeyToX509Backing[key] ?: key.genericCurveFallback()?.let(signatureKeyToX509Backing::get)
                }
        }

    fun registerBuiltIns() {
        ensureBuiltIns()
    }

    internal val signatureEcdsaSha256 =
        AlgorithmRegistry.registerSignatureAlgorithm(EcdsaSignatureAlgorithm(Digest.SHA256, null), ensure = false)
    internal val signatureEcdsaSha384 =
        AlgorithmRegistry.registerSignatureAlgorithm(EcdsaSignatureAlgorithm(Digest.SHA384, null), ensure = false)
    internal val signatureEcdsaSha512 =
        AlgorithmRegistry.registerSignatureAlgorithm(EcdsaSignatureAlgorithm(Digest.SHA512, null), ensure = false)
    internal val signatureRsaSha256Pkcs1 =
        AlgorithmRegistry.registerSignatureAlgorithm(
            RsaSignatureAlgorithm(Digest.SHA256, RsaSignaturePadding.PKCS1),
            ensure = false
        )
    internal val signatureRsaSha384Pkcs1 =
        AlgorithmRegistry.registerSignatureAlgorithm(
            RsaSignatureAlgorithm(Digest.SHA384, RsaSignaturePadding.PKCS1),
            ensure = false
        )
    internal val signatureRsaSha512Pkcs1 =
        AlgorithmRegistry.registerSignatureAlgorithm(
            RsaSignatureAlgorithm(Digest.SHA512, RsaSignaturePadding.PKCS1),
            ensure = false
        )
    internal val signatureRsaSha256Pss =
        AlgorithmRegistry.registerSignatureAlgorithm(
            RsaSignatureAlgorithm(Digest.SHA256, RsaSignaturePadding.PSS),
            ensure = false
        )
    internal val signatureRsaSha384Pss =
        AlgorithmRegistry.registerSignatureAlgorithm(
            RsaSignatureAlgorithm(Digest.SHA384, RsaSignaturePadding.PSS),
            ensure = false
        )
    internal val signatureRsaSha512Pss =
        AlgorithmRegistry.registerSignatureAlgorithm(
            RsaSignatureAlgorithm(Digest.SHA512, RsaSignaturePadding.PSS),
            ensure = false
        )

}

private fun SignatureMappingKey.genericCurveFallback(): SignatureMappingKey? =
    if ((family == EcdsaSignatureMappingFamily) && (curve != null)) copy(curve = null) else null

@OptIn(HazardousMaterials::class)
private fun registerInternalBuiltIns() {
    AlgorithmRegistry.registerSignatureRsaPadding(Pkcs1RsaSignaturePadding, false)
    AlgorithmRegistry.registerSignatureRsaPadding(PssRsaSignaturePadding, false)

    AlgorithmRegistry.signatureEcdsaSha256
    AlgorithmRegistry.signatureEcdsaSha384
    AlgorithmRegistry.signatureEcdsaSha512
    AlgorithmRegistry.signatureRsaSha256Pkcs1
    AlgorithmRegistry.signatureRsaSha384Pkcs1
    AlgorithmRegistry.signatureRsaSha512Pkcs1
    AlgorithmRegistry.signatureRsaSha256Pss
    AlgorithmRegistry.signatureRsaSha384Pss
    AlgorithmRegistry.signatureRsaSha512Pss

    MessageAuthenticationCode.HMAC_SHA1
    MessageAuthenticationCode.HMAC_SHA256
    MessageAuthenticationCode.HMAC_SHA384
    MessageAuthenticationCode.HMAC_SHA512

    AlgorithmRegistry.registerAsymmetricRsaPadding(
        at.asitplus.signum.indispensable.asymmetric.Pkcs1RsaEncryptionPadding,
        false
    )
    AlgorithmRegistry.registerAsymmetricRsaPadding(
        at.asitplus.signum.indispensable.asymmetric.NoRsaEncryptionPadding,
        false
    )
    AlgorithmRegistry.registerAsymmetricRsaPadding(
        at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha1,
        false
    )
    AlgorithmRegistry.registerAsymmetricRsaPadding(
        at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha256,
        false
    )
    AlgorithmRegistry.registerAsymmetricRsaPadding(
        at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha384,
        false
    )
    AlgorithmRegistry.registerAsymmetricRsaPadding(
        at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha512,
        false
    )

    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.NoRsaEncryptionPadding),
        false
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.Pkcs1RsaEncryptionPadding),
        false
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha1),
        false
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha256),
        false
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha384),
        false
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha512),
        false
    )

    AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(
        SymmetricEncryptionAlgorithm.ChaCha20Poly1305,
        ensure = false
    )
    SymmetricEncryptionAlgorithm.AES_128.entries.forEach {
        AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(
            it,
            false
        )
    }
    SymmetricEncryptionAlgorithm.AES_192.entries.forEach {
        AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(
            it,
            false
        )
    }
    SymmetricEncryptionAlgorithm.AES_256.entries.forEach {
        AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(
            it,
            false
        )
    }

    X509SignatureAlgorithm.entries
}

