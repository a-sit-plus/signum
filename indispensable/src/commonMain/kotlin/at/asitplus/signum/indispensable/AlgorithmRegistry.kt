package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionPadding
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionAlgorithm
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
    private val exactSymmetricMappingsBacking = linkedMapOf<String, LinkedHashMap<SymmetricEncryptionAlgorithm<*, *, *>, Any>>()
    private val asymmetricMappingsBacking = linkedMapOf<String, LinkedHashMap<AsymmetricEncryptionMappingKey, Any>>()
    private val exactAsymmetricMappingsBacking = linkedMapOf<String, LinkedHashMap<AsymmetricEncryptionAlgorithm, Any>>()
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

    fun <T : SignatureAlgorithm> registerSignatureAlgorithm(algorithm: T): T = algorithm.also {
        ensureBuiltIns()
        signatureAlgorithmsBacking += it
        dataIntegrityAlgorithmsBacking += it
    }

    fun <T : MessageAuthenticationCode> registerMessageAuthenticationCode(algorithm: T): T = algorithm.also {
        ensureBuiltIns()
        messageAuthenticationCodesBacking += it
        dataIntegrityAlgorithmsBacking += it
    }

    fun <T : SymmetricEncryptionAlgorithm<*, *, *>> registerSymmetricEncryptionAlgorithm(algorithm: T): T =
        algorithm.also {
            ensureBuiltIns()
            symmetricEncryptionAlgorithmsBacking += it
        }

    fun <T : RsaSignaturePadding> registerSignatureRsaPadding(padding: T): T = padding.also {
        ensureBuiltIns()
        signatureRsaPaddingsBacking += it
    }

    fun <T : RsaEncryptionPadding> registerAsymmetricRsaPadding(padding: T): T = padding.also {
        ensureBuiltIns()
        asymmetricRsaPaddingsBacking += it
    }

    fun <T : AsymmetricEncryptionAlgorithm> registerAsymmetricEncryptionAlgorithm(algorithm: T): T = algorithm.also {
        ensureBuiltIns()
        asymmetricEncryptionAlgorithmsBacking += it
    }

    fun <T : Any> registerSignatureMapping(namespace: String, key: SignatureMappingKey, target: T): T = target.also {
        ensureBuiltIns()
        signatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerSignatureMapping(namespace: String, algorithm: SignatureAlgorithm, target: T): T = target.also {
        ensureBuiltIns()
        exactSignatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
        algorithm.signatureMappingKeyOrNull()?.let { key ->
            signatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap).putIfAbsent(key, it)
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

    fun <T : Any> registerMacMapping(namespace: String, algorithm: MessageAuthenticationCode, target: T): T = target.also {
        ensureBuiltIns()
        exactMacMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
        algorithm.macMappingKeyOrNull()?.let { key ->
            macMappingsBacking.getOrPut(namespace, ::LinkedHashMap).putIfAbsent(key, it)
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

    fun <T : Any> registerSymmetricMapping(namespace: String, algorithm: SymmetricEncryptionAlgorithm<*, *, *>, target: T): T = target.also {
        ensureBuiltIns()
        exactSymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
        algorithm.symmetricMappingKeyOrNull()?.let { key ->
            symmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap).putIfAbsent(key, it)
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findSymmetricMapping(namespace: String, algorithm: SymmetricEncryptionAlgorithm<*, *, *>): T? =
        ensureBuiltIns().let {
            (exactSymmetricMappingsBacking[namespace]?.get(algorithm) as? T)
                ?: algorithm.symmetricMappingKeyOrNull()?.let { symmetricMappingsBacking[namespace]?.get(it) as? T }
        }

    fun <T : Any> registerAsymmetricMapping(namespace: String, key: AsymmetricEncryptionMappingKey, target: T): T = target.also {
        ensureBuiltIns()
        asymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerAsymmetricMapping(namespace: String, algorithm: AsymmetricEncryptionAlgorithm, target: T): T = target.also {
        ensureBuiltIns()
        exactAsymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
        algorithm.asymmetricEncryptionMappingKeyOrNull()?.let { key ->
            asymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap).putIfAbsent(key, it)
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findAsymmetricMapping(namespace: String, algorithm: AsymmetricEncryptionAlgorithm): T? =
        ensureBuiltIns().let {
            (exactAsymmetricMappingsBacking[namespace]?.get(algorithm) as? T)
                ?: algorithm.asymmetricEncryptionMappingKeyOrNull()?.let { asymmetricMappingsBacking[namespace]?.get(it) as? T }
        }

    fun registerX509SignatureMapping(raw: SignatureAlgorithmIdentifier, algorithm: SignatureAlgorithm): SignatureAlgorithm = algorithm.also {
        ensureBuiltIns()
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
}
    private fun SignatureMappingKey.genericCurveFallback(): SignatureMappingKey? =
        if ((family == EcdsaSignatureMappingFamily) && (curve != null)) copy(curve = null) else null

@OptIn(HazardousMaterials::class)
private fun registerInternalBuiltIns() {
    AlgorithmRegistry.registerSignatureRsaPadding(Pkcs1RsaSignaturePadding)
    AlgorithmRegistry.registerSignatureRsaPadding(PssRsaSignaturePadding)

    SignatureAlgorithm.ECDSA_SHA256
    SignatureAlgorithm.ECDSA_SHA384
    SignatureAlgorithm.ECDSA_SHA512
    SignatureAlgorithm.RSA_SHA256_PKCS1
    SignatureAlgorithm.RSA_SHA384_PKCS1
    SignatureAlgorithm.RSA_SHA512_PKCS1
    SignatureAlgorithm.RSA_SHA256_PSS
    SignatureAlgorithm.RSA_SHA384_PSS
    SignatureAlgorithm.RSA_SHA512_PSS

    MessageAuthenticationCode.HMAC_SHA1
    MessageAuthenticationCode.HMAC_SHA256
    MessageAuthenticationCode.HMAC_SHA384
    MessageAuthenticationCode.HMAC_SHA512

    AlgorithmRegistry.registerAsymmetricRsaPadding(at.asitplus.signum.indispensable.asymmetric.Pkcs1RsaEncryptionPadding)
    AlgorithmRegistry.registerAsymmetricRsaPadding(at.asitplus.signum.indispensable.asymmetric.NoRsaEncryptionPadding)
    AlgorithmRegistry.registerAsymmetricRsaPadding(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha1)
    AlgorithmRegistry.registerAsymmetricRsaPadding(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha256)
    AlgorithmRegistry.registerAsymmetricRsaPadding(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha384)
    AlgorithmRegistry.registerAsymmetricRsaPadding(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha512)

    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.NoRsaEncryptionPadding)
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.Pkcs1RsaEncryptionPadding)
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha1)
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha256)
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha384)
    )
    AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(
        RsaEncryptionAlgorithm(at.asitplus.signum.indispensable.asymmetric.OaepRsaEncryptionPadding.Sha512)
    )

    AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.ChaCha20Poly1305)
    at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES_128.entries.forEach(AlgorithmRegistry::registerSymmetricEncryptionAlgorithm)
    at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES_192.entries.forEach(AlgorithmRegistry::registerSymmetricEncryptionAlgorithm)
    at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.AES_256.entries.forEach(AlgorithmRegistry::registerSymmetricEncryptionAlgorithm)

    X509SignatureAlgorithm.entries
}
