package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.SignatureAlgorithmIdentifier
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asymmetric.*
import at.asitplus.signum.indispensable.symmetric.ChaCha20Poly1305Algorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.Companion.AES_128
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.Companion.AES_192
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm.Companion.AES_256

/**
 * Global registry of built-in and third-party algorithms.
 *
 * Third-party code can register custom algorithms to participate in lookups and enumeration.
 */

//TODO: Unscrew this. called from all sorts of places, init is a mess, etc.
//for builtins it should be possible to get an init call done
@OptIn(HazardousMaterials::class)
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

    private val x509SignatureAlgorithmsBacking = linkedSetOf<X509SignatureAlgorithm>()
    private val signatureAlgorithmsBacking = linkedSetOf<SignatureAlgorithm>()
    private val dataIntegrityAlgorithmsBacking = linkedSetOf<DataIntegrityAlgorithm>()
    private val messageAuthenticationCodesBacking = linkedSetOf<MessageAuthenticationCode>()
    private val symmetricEncryptionAlgorithmsBacking = linkedSetOf<SymmetricEncryptionAlgorithm<*, *, *>>()
    private val signatureRsaPaddingsBacking = linkedSetOf<RsaSignaturePadding>()
    private val asymmetricRsaPaddingsBacking = linkedSetOf<RsaEncryptionPadding>()
    private val asymmetricEncryptionAlgorithmsBacking = linkedSetOf<AsymmetricEncryptionAlgorithm>()

    val x509SignatureAlgorithms: List<X509SignatureAlgorithm> get() = x509SignatureAlgorithmsBacking.toList()

    val signatureAlgorithms: List<SignatureAlgorithm>
        get() {
            return signatureAlgorithmsBacking.toList()
        }
    val dataIntegrityAlgorithms: List<DataIntegrityAlgorithm>
        get() {
            return dataIntegrityAlgorithmsBacking.toList()
        }
    val messageAuthenticationCodes: List<MessageAuthenticationCode>
        get() {
            return messageAuthenticationCodesBacking.toList()
        }
    val symmetricEncryptionAlgorithms: List<SymmetricEncryptionAlgorithm<*, *, *>>
        get() {
            return symmetricEncryptionAlgorithmsBacking.toList()
        }
    val signatureRsaPaddings: List<RsaSignaturePadding>
        get() {
            return signatureRsaPaddingsBacking.toList()
        }
    val asymmetricRsaPaddings: List<RsaEncryptionPadding>
        get() {
            return asymmetricRsaPaddingsBacking.toList()
        }
    val asymmetricEncryptionAlgorithms: List<AsymmetricEncryptionAlgorithm>
        get() {
            return asymmetricEncryptionAlgorithmsBacking.toList()
        }

    init {
        registerSignatureRsaPadding(Pkcs1RsaSignaturePadding)
        registerSignatureRsaPadding(PssRsaSignaturePadding)

        listOf(
            (RsaEncryptionPadding.NONE),
            (RsaEncryptionPadding.PKCS1),
            (RsaEncryptionPadding.OAEP_SHA1),
            (RsaEncryptionPadding.OAEP_SHA256),
            (RsaEncryptionPadding.OAEP_SHA384),
            (RsaEncryptionPadding.OAEP_SHA512),
        ).forEach { registerAsymmetricRsaPadding(it) }

        listOf(

            AsymmetricEncryptionAlgorithm.Companion.RSA_PKCS1,
            AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA256,
            AsymmetricEncryptionAlgorithm.Companion.RSA_NONE,
            AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA1,
            AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA384,
            AsymmetricEncryptionAlgorithm.Companion.RSA_OAEP_SHA512,
        ).forEach { registerAsymmetricEncryptionAlgorithm(it) }



        listOf(
            MessageAuthenticationCode.Companion.HMAC_SHA1,
            MessageAuthenticationCode.Companion.HMAC_SHA256,
            MessageAuthenticationCode.Companion.HMAC_SHA384,
            MessageAuthenticationCode.Companion.HMAC_SHA512
        ).forEach {
            registerMessageAuthenticationCode(it)
        }

        listOf(
            SignatureAlgorithm.Companion.ECDSA_SHA256,
            SignatureAlgorithm.Companion.ECDSA_SHA384,
            SignatureAlgorithm.Companion.ECDSA_SHA512,
            SignatureAlgorithm.Companion.RSA_SHA256_PKCS1,
            SignatureAlgorithm.Companion.RSA_SHA384_PKCS1,
            SignatureAlgorithm.Companion.RSA_SHA512_PKCS1,
            SignatureAlgorithm.Companion.RSA_SHA256_PSS,
            SignatureAlgorithm.Companion.RSA_SHA384_PSS,
            SignatureAlgorithm.Companion.RSA_SHA512_PSS,
        ).forEach { registerSignatureAlgorithm(it) }

        (listOf(ChaCha20Poly1305Algorithm) + AES_128.entries + AES_192.entries + AES_256.entries)
            .onEach { AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(it) }


        registerSymmetricEncryptionAlgorithm(
            SymmetricEncryptionAlgorithm.ChaCha20Poly1305,
        )
        SymmetricEncryptionAlgorithm.AES_128.entries.forEach {
            registerSymmetricEncryptionAlgorithm(
                it,
            )
        }
        SymmetricEncryptionAlgorithm.AES_192.entries.forEach {
            registerSymmetricEncryptionAlgorithm(
                it,
            )
        }
        SymmetricEncryptionAlgorithm.AES_256.entries.forEach {
            registerSymmetricEncryptionAlgorithm(
                it,
            )
        }

        listOf(
            X509SignatureAlgorithm.Companion.ES256,
            X509SignatureAlgorithm.Companion.ES384,
            X509SignatureAlgorithm.Companion.ES512,
            X509SignatureAlgorithm.Companion.PS256,
            X509SignatureAlgorithm.Companion.PS384,
            X509SignatureAlgorithm.Companion.PS512,
            X509SignatureAlgorithm.Companion.RS1,
            X509SignatureAlgorithm.Companion.RS256,
            X509SignatureAlgorithm.Companion.RS384,
            X509SignatureAlgorithm.Companion.RS512
        ).forEach {
            registerX509SignatureMapping(it)
        }
    }

    fun <T : SignatureAlgorithm> registerSignatureAlgorithm(algorithm: T): T =
        algorithm.also {
            signatureAlgorithmsBacking += it
            dataIntegrityAlgorithmsBacking += it
        }

    fun <T : MessageAuthenticationCode> registerMessageAuthenticationCode(algorithm: T): T =
        algorithm.also {
            messageAuthenticationCodesBacking += it
            dataIntegrityAlgorithmsBacking += it
        }

    fun <T : SymmetricEncryptionAlgorithm<*, *, *>> registerSymmetricEncryptionAlgorithm(
        algorithm: T,
    ): T =
        algorithm.also {
            symmetricEncryptionAlgorithmsBacking += it
        }

    fun <T : RsaSignaturePadding> registerSignatureRsaPadding(padding: T): T = padding.also {
        signatureRsaPaddingsBacking += it
    }

    fun <T : RsaEncryptionPadding> registerAsymmetricRsaPadding(padding: T): T =
        padding.also {
            asymmetricRsaPaddingsBacking += it
        }

    fun <T : AsymmetricEncryptionAlgorithm> registerAsymmetricEncryptionAlgorithm(
        algorithm: T,
    ): T = algorithm.also {
        asymmetricEncryptionAlgorithmsBacking += it
    }

    fun <T : Any> registerSignatureMapping(
        namespace: String,
        key: SignatureMappingKey,
        target: T,
    ): T = target.also {
        signatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerSignatureMapping(namespace: String, algorithm: SignatureAlgorithm, target: T): T =
        target.also {
            exactSignatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
            algorithm.signatureMappingKeyOrNull()?.let { key ->
                signatureMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                    if (!contains(key)) put(key, it)
                }
            }
        }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findSignatureMapping(namespace: String, algorithm: SignatureAlgorithm): T? =
        (exactSignatureMappingsBacking[namespace]?.get(algorithm) as? T)
            ?: algorithm.signatureMappingKeyOrNull()?.let { key ->
                (signatureMappingsBacking[namespace]?.get(key) as? T)
                    ?: key.genericCurveFallback()?.let { signatureMappingsBacking[namespace]?.get(it) as? T }
            }


    fun <T : Any> registerMacMapping(namespace: String, key: MacMappingKey, target: T): T = target.also {
        macMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerMacMapping(namespace: String, algorithm: MessageAuthenticationCode, target: T): T =
        target.also {
            exactMacMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
            algorithm.macMappingKeyOrNull()?.let { key ->
                macMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                    if (!contains(key)) put(key, it)
                }
            }
        }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findMacMapping(namespace: String, algorithm: MessageAuthenticationCode): T? =
        (exactMacMappingsBacking[namespace]?.get(algorithm) as? T)
            ?: algorithm.macMappingKeyOrNull()?.let { macMappingsBacking[namespace]?.get(it) as? T }

    fun <T : Any> registerSymmetricMapping(namespace: String, key: SymmetricMappingKey, target: T): T = target.also {
        symmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
    }

    fun <T : Any> registerSymmetricMapping(
        namespace: String,
        algorithm: SymmetricEncryptionAlgorithm<*, *, *>,
        target: T
    ): T = target.also {
        exactSymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
        algorithm.symmetricMappingKeyOrNull()?.let { key ->
            symmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                if (!contains(key)) put(key, it)
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findSymmetricMapping(namespace: String, algorithm: SymmetricEncryptionAlgorithm<*, *, *>): T? =
        (exactSymmetricMappingsBacking[namespace]?.get(algorithm) as? T)
            ?: algorithm.symmetricMappingKeyOrNull()?.let { symmetricMappingsBacking[namespace]?.get(it) as? T }


    fun <T : Any> registerAsymmetricMapping(
        namespace: String,
        key: AsymmetricEncryptionMappingKey,
        target: T,
    ): T =
        target.also {
            asymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[key] = it
        }

    fun <T : Any> registerAsymmetricMapping(namespace: String, algorithm: AsymmetricEncryptionAlgorithm, target: T): T =
        target.also {
            exactAsymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap)[algorithm] = it
            algorithm.asymmetricEncryptionMappingKeyOrNull()?.let { key ->
                asymmetricMappingsBacking.getOrPut(namespace, ::LinkedHashMap).apply {
                    if (!contains(key)) put(key, it)
                }
            }
        }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> findAsymmetricMapping(namespace: String, algorithm: AsymmetricEncryptionAlgorithm): T? =
        (exactAsymmetricMappingsBacking[namespace]?.get(algorithm) as? T)
            ?: algorithm.asymmetricEncryptionMappingKeyOrNull()
                ?.let { asymmetricMappingsBacking[namespace]?.get(it) as? T }


    fun registerX509SignatureMapping(
        alg: X509SignatureAlgorithm,
    ): X509SignatureAlgorithm = alg.also {

        val raw: SignatureAlgorithmIdentifier = it.raw
        val algorithm: SignatureAlgorithm = it.algorithm
        val rawKey = X509SignatureKey(raw.oid, raw.parameters)
        x509ToSignatureBacking[rawKey] = algorithm
        signatureToX509Backing[algorithm] = raw
        algorithm.signatureMappingKeyOrNull()?.let { signatureKeyToX509Backing[it] = raw }
        x509SignatureAlgorithmsBacking += it

    }

    fun findSignatureAlgorithm(raw: SignatureAlgorithmIdentifier): SignatureAlgorithm? =
        x509ToSignatureBacking[X509SignatureKey(raw.oid, raw.parameters)]

    fun findX509SignatureIdentifier(algorithm: SignatureAlgorithm): SignatureAlgorithmIdentifier? =
        signatureToX509Backing[algorithm]
            ?: algorithm.signatureMappingKeyOrNull()?.let { key ->
                signatureKeyToX509Backing[key] ?: key.genericCurveFallback()?.let(signatureKeyToX509Backing::get)
            }

}

private fun SignatureMappingKey.genericCurveFallback(): SignatureMappingKey? =
    if ((family == EcdsaSignatureMappingFamily) && (curve != null)) copy(curve = null) else null


