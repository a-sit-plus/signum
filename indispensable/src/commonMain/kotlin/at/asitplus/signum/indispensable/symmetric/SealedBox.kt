package at.asitplus.signum.indispensable.symmetric

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

/**
 * Represents symmetrically encrypted data in a structured manner.
 * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
 */
sealed interface SealedBox<out E: SymmetricEncryptionAlgorithm<*, *>> {
    val algorithm: E
    val encryptedData: ByteArray

    typealias Authenticated<I> = SealedBox<SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, I>>

    typealias Unauthenticated<I> = SealedBox<SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I>>

    typealias WithoutNonce<A> = SealedBox<SymmetricEncryptionAlgorithm.WithoutNonce<A>>

    typealias WithNonce<A> = SealedBox<SymmetricEncryptionAlgorithm.RequiringNonce<A>>
    companion object {
        fun< E: SymmetricEncryptionAlgorithm.WithoutNonce<*>> WithoutNonce(
            ciphertext: Ciphertext<E>
        ): SealedBox<E> = SealedBoxFromCiphertextWithoutNonce(ciphertext)
        fun <E: SymmetricEncryptionAlgorithm.RequiringNonce<*>> WithNonce(
            nonce: ByteArray,
            ciphertext: Ciphertext<E>
        ): SealedBox<E> = SealedBoxFromCiphertextWithNonce(nonce, ciphertext)
    }
}

val SealedBox.WithNonce<*>.nonce: ByteArray get() = when (this) {
    is SealedBoxFromCiphertext -> when (this) {
        is SealedBoxFromCiphertextWithNonce -> nonce
        is SealedBoxFromCiphertextWithoutNonce<*> -> ciphertext.algorithm.absurdNonce()
    }
}

val SealedBox.Authenticated<*>.authTag: ByteArray get() = when (this) {
    is SealedBoxFromCiphertext -> when (ciphertext) {
        is CipherTextAuthenticated<*> -> ciphertext.authTag
        is CipherTextUnauthenticated<*> -> ciphertext.algorithm.absurd()
    }
}

private sealed class SealedBoxFromCiphertext<E: SymmetricEncryptionAlgorithm<*, *>>(
    val ciphertext: Ciphertext<E>
) : SealedBox<E> {
    override val algorithm: E = ciphertext.algorithm
    override val encryptedData: ByteArray = ciphertext.encryptedData
}

private class SealedBoxFromCiphertextWithoutNonce<E: SymmetricEncryptionAlgorithm<*, NonceTrait.Without>>(
    ciphertext: Ciphertext<E>
) : SealedBoxFromCiphertext<E>(ciphertext) {
    override fun toString(): String = "SealedBox.WithoutNonce(ciphertext=$ciphertext)"
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SealedBoxFromCiphertextWithoutNonce<*>) return false

        if (ciphertext != other.ciphertext) return false
        if (algorithm != other.algorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = ciphertext.hashCode()
        result = 31 * result + algorithm.hashCode()
        return result
    }
}

private class SealedBoxFromCiphertextWithNonce<E: SymmetricEncryptionAlgorithm<*, NonceTrait.Required>>(
    val nonce: ByteArray,
    ciphertext: Ciphertext<E>
) : SealedBoxFromCiphertext<E>(ciphertext) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SealedBoxFromCiphertextWithNonce<*>) return false

        if (!nonce.contentEquals(other.nonce)) return false
        if (ciphertext != other.ciphertext) return false
        if (algorithm != other.algorithm) return false

        return true
    }

    override fun hashCode(): Int {
        var result = nonce.contentHashCode()
        result = 31 * result + ciphertext.hashCode()
        result = 31 * result + algorithm.hashCode()
        return result
    }

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String =
        "SealedBox.WithNonce(nonce=${nonce.toHexString(HexFormat.UpperCase)}, ciphertext=$ciphertext)"
}

/**
 * A generic ciphertext object, referencing the algorithm it was created by.
 */
sealed interface Ciphertext<out E : SymmetricEncryptionAlgorithm<*, *>> {
    val algorithm: E
    val encryptedData: ByteArray

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    typealias Authenticated = Ciphertext<SymmetricEncryptionAlgorithm.Authenticated<*>>

    /**
     * An Unauthenticated ciphertext
     */
    typealias Unauthenticated<E> = Ciphertext<SymmetricEncryptionAlgorithm.Unauthenticated<*>>

    companion object {
        internal fun <E : SymmetricEncryptionAlgorithm.Authenticated<*>> Authenticated(
            algorithm: E,
            encryptedData: ByteArray,
            authTag: ByteArray
        ): Ciphertext<E> = CipherTextAuthenticated(algorithm, encryptedData, authTag)
        internal fun <E : SymmetricEncryptionAlgorithm.Unauthenticated<*>> Unauthenticated(
            algorithm: E,
            encryptedData: ByteArray
        ): Ciphertext<E> = CipherTextUnauthenticated(algorithm, encryptedData)
    }
}

private class CipherTextAuthenticated<E : SymmetricEncryptionAlgorithm.Authenticated<*>>(
    override val algorithm: E,
    override val encryptedData: ByteArray,
    val authTag: ByteArray,
) : Ciphertext<E> {
    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String =
        "$algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, authTag=${
            authTag.toHexString(HexFormat.UpperCase)
        })"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CipherTextAuthenticated<*>) return false

        if (algorithm != other.algorithm) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false
        if (!authTag.contentEquals(other.authTag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        result = 31 * result + authTag.contentHashCode()
        return result
    }
}

private class CipherTextUnauthenticated<E : SymmetricEncryptionAlgorithm.Unauthenticated<*>>(
    override val algorithm: E,
    override val encryptedData: ByteArray,
) : Ciphertext<E> {

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String =
        "$algorithm Unauthenticated Ciphertext(encryptedData=${
            encryptedData.toHexString(HexFormat.UpperCase)
        })"

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CipherTextUnauthenticated<*>) return false
        if (algorithm != other.algorithm) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false
        return true
    }

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        return result
    }
}

/**Use to smart-cast this sealed box*/
@OptIn(ExperimentalContracts::class)
fun <I: NonceTrait<*>> SealedBox<SymmetricEncryptionAlgorithm<*, I>>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SealedBox.Authenticated<I>)
        returns(false) implies (this@isAuthenticated is SealedBox.Unauthenticated<I>)
    }
    return algorithm.isAuthenticated()
}

/**Use to smart-cast this sealed box*/
@OptIn(ExperimentalContracts::class)
fun <A: AuthCapability<*>> SealedBox<SymmetricEncryptionAlgorithm<A, *>>.hasNonce(): Boolean {
    contract {
        returns(true) implies (this@hasNonce is SealedBox.WithNonce<A>)
        returns(false) implies (this@hasNonce is SealedBox.WithoutNonce<A>)
    }
    return algorithm.requiresNonce()
}


/**Use to smart-cast this sealed box*/
@OptIn(ExperimentalContracts::class)
fun <I : NonceTrait<*>> SealedBox<SymmetricEncryptionAlgorithm<*, I>>.hasMacKey(): Boolean {
    contract {
        returns(true) implies (this@hasMacKey is SealedBox<SymmetricEncryptionAlgorithm.EncryptThenMAC<I>>)
        returns(false) implies (this@hasMacKey is SealedBox<SymmetricEncryptionAlgorithm.Integrated<I>>)
    }
    return algorithm.hasDedicatedMac()
}
