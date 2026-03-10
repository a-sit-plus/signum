package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionPadding
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm

/**
 * Global registry of built-in and third-party algorithms.
 *
 * Third-party code can register custom algorithms to participate in lookups and enumeration.
 */
object AlgorithmRegistry {
    private val signatureAlgorithmsBacking = linkedSetOf<SignatureAlgorithm>()
    private val dataIntegrityAlgorithmsBacking = linkedSetOf<DataIntegrityAlgorithm>()
    private val messageAuthenticationCodesBacking = linkedSetOf<MessageAuthenticationCode>()
    private val symmetricEncryptionAlgorithmsBacking = linkedSetOf<SymmetricEncryptionAlgorithm<*, *, *>>()
    private val signatureRsaPaddingsBacking = linkedSetOf<RsaSignaturePadding>()
    private val asymmetricRsaPaddingsBacking = linkedSetOf<RsaEncryptionPadding>()
    private val asymmetricEncryptionAlgorithmsBacking = linkedSetOf<AsymmetricEncryptionAlgorithm>()

    val signatureAlgorithms: List<SignatureAlgorithm> get() = signatureAlgorithmsBacking.toList()
    val dataIntegrityAlgorithms: List<DataIntegrityAlgorithm> get() = dataIntegrityAlgorithmsBacking.toList()
    val messageAuthenticationCodes: List<MessageAuthenticationCode> get() = messageAuthenticationCodesBacking.toList()
    val symmetricEncryptionAlgorithms: List<SymmetricEncryptionAlgorithm<*, *, *>> get() = symmetricEncryptionAlgorithmsBacking.toList()
    val signatureRsaPaddings: List<RsaSignaturePadding> get() = signatureRsaPaddingsBacking.toList()
    val asymmetricRsaPaddings: List<RsaEncryptionPadding> get() = asymmetricRsaPaddingsBacking.toList()
    val asymmetricEncryptionAlgorithms: List<AsymmetricEncryptionAlgorithm> get() = asymmetricEncryptionAlgorithmsBacking.toList()

    fun <T : SignatureAlgorithm> registerSignatureAlgorithm(algorithm: T): T = algorithm.also {
        signatureAlgorithmsBacking += it
        dataIntegrityAlgorithmsBacking += it
    }

    fun <T : MessageAuthenticationCode> registerMessageAuthenticationCode(algorithm: T): T = algorithm.also {
        messageAuthenticationCodesBacking += it
        dataIntegrityAlgorithmsBacking += it
    }

    fun <T : SymmetricEncryptionAlgorithm<*, *, *>> registerSymmetricEncryptionAlgorithm(algorithm: T): T =
        algorithm.also { symmetricEncryptionAlgorithmsBacking += it }

    fun <T : RsaSignaturePadding> registerSignatureRsaPadding(padding: T): T = padding.also {
        signatureRsaPaddingsBacking += it
    }

    fun <T : RsaEncryptionPadding> registerAsymmetricRsaPadding(padding: T): T = padding.also {
        asymmetricRsaPaddingsBacking += it
    }

    fun <T : AsymmetricEncryptionAlgorithm> registerAsymmetricEncryptionAlgorithm(algorithm: T): T = algorithm.also {
        asymmetricEncryptionAlgorithmsBacking += it
    }
}
