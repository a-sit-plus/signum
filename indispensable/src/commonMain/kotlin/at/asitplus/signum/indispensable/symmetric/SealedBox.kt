package at.asitplus.signum.indispensable.symmetric

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

val <I : NonceTrait> SealedBox<out AuthCapability.Authenticated, I>.authTag
    get() = (this as SealedBox.Authenticated).authTag

val SealedBox<*, NonceTrait.Required>.nonce get() = (this as SealedBox.WithNonce).nonce

/**
 * Represents symmetrically encrypted data in a structured manner.
 * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
 */
sealed interface SealedBox<A : AuthCapability, I : NonceTrait> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I>
    val encryptedData: ByteArray

    interface Authenticated<I : NonceTrait> :
        SealedBox<AuthCapability.Authenticated, I> {
        val authTag: ByteArray
    }

    interface Unauthenticated<I : NonceTrait> :
        SealedBox<AuthCapability.Unauthenticated, I>

    /**
     * A sealed box without an IV/nonce.
     * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
     */
    sealed class WithoutNonce<A : AuthCapability>(
        private val ciphertext: Ciphertext<A, NonceTrait.Without, SymmetricEncryptionAlgorithm<A, NonceTrait.Without>>
    ) : SealedBox<A, NonceTrait.Without> {

        override val algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Without> = ciphertext.algorithm
        override val encryptedData: ByteArray = ciphertext.encryptedData

        override fun toString(): String = "SealedBox.WithoutNonce(ciphertext=$ciphertext)"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithoutNonce<*>) return false

            if (ciphertext != other.ciphertext) return false
            if (algorithm != other.algorithm) return false

            return true
        }

        override fun hashCode(): Int {
            var result = ciphertext.hashCode()
            result = 31 * result + algorithm.hashCode()
            return result
        }

        class Unauthenticated
        internal constructor(ciphertext: Ciphertext.Unauthenticated<NonceTrait.Without>) :
            WithoutNonce<AuthCapability.Unauthenticated>(ciphertext),
            SealedBox.Unauthenticated<NonceTrait.Without>

        class Authenticated
        internal constructor(ciphertext: Ciphertext.Authenticated<AuthCapability.Authenticated, NonceTrait.Without, SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, NonceTrait.Without>>) :
            WithoutNonce<AuthCapability.Authenticated>(ciphertext),
            SealedBox.Authenticated<NonceTrait.Without> {
            override val authTag = ciphertext.authTag
        }
    }

    /**
     * A sealed box consisting of an [nonce] and the actual [ciphertext].
     * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
     */
    sealed class WithNonce<A : AuthCapability>(
        val nonce: ByteArray,
        private val ciphertext: Ciphertext<A, NonceTrait.Required, SymmetricEncryptionAlgorithm<A, NonceTrait.Required>>
    ) : SealedBox<A, NonceTrait.Required> {

        override val algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required> = ciphertext.algorithm
        override val encryptedData: ByteArray = ciphertext.encryptedData


        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithNonce<*>) return false

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

        class Unauthenticated
        internal constructor(nonce: ByteArray, ciphertext: Ciphertext.Unauthenticated<NonceTrait.Required>) :
            WithNonce<AuthCapability.Unauthenticated>(nonce, ciphertext),
            SealedBox.Unauthenticated<NonceTrait.Required>

        class Authenticated
        internal constructor(
            nonce: ByteArray,
            ciphertext: Ciphertext.Authenticated<AuthCapability.Authenticated, NonceTrait.Required, SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, NonceTrait.Required>>
        ) :
            WithNonce<AuthCapability.Authenticated>(nonce, ciphertext),
            SealedBox.Authenticated<NonceTrait.Required> {
            override val authTag = ciphertext.authTag
        }
    }
}


/**
 * A generic ciphertext object, referencing the algorithm it was created by.
 */
sealed interface Ciphertext<A : AuthCapability, I : NonceTrait, E : SymmetricEncryptionAlgorithm<A, I>> {
    val algorithm: E
    val encryptedData: ByteArray

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    class Authenticated<A : AuthCapability.Authenticated, I : NonceTrait, E : SymmetricEncryptionAlgorithm<A, I>> internal constructor(
        override val algorithm: E,
        override val encryptedData: ByteArray,
        val authTag: ByteArray,
    ) : Ciphertext<A, I, E> {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, authTag=${
                authTag.toHexString(HexFormat.UpperCase)
            })"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Authenticated<*, *, *>) return false

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

    /**
     * An Unauthenticated ciphertext
     */
    class Unauthenticated<I : NonceTrait> internal constructor(
        override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I>,
        override val encryptedData: ByteArray,
    ) : Ciphertext<AuthCapability.Unauthenticated, I,
            SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I>> {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Unauthenticated Ciphertext(encryptedData=${
                encryptedData.toHexString(HexFormat.UpperCase)
            })"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Unauthenticated<*>) return false
            if (algorithm != other.algorithm) return false
            if (!encryptedData.contentEquals(other.encryptedData)) return false
            return true
        }

        override fun hashCode(): Int {
            return super.hashCode()
        }
    }
}

/**Use to smart-cast this sealed box*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability, I : NonceTrait> SealedBox<A, I>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SealedBox.Authenticated<I>)
        returns(false) implies (this@isAuthenticated is SealedBox.Unauthenticated<I>)
    }
    return this.algorithm.authCapability is AuthCapability.Authenticated
}

/**Use to smart-cast this sealed box*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability, I : NonceTrait> SealedBox<A, I>.hasNonce(): Boolean {
    contract {
        returns(true) implies (this@hasNonce is SealedBox.WithNonce<A>)
        returns(false) implies (this@hasNonce is SealedBox.WithoutNonce<A>)
    }
    return algorithm.nonceTrait is NonceTrait.Required
}
