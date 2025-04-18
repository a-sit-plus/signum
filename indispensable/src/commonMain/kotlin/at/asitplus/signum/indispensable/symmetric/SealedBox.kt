package at.asitplus.signum.indispensable.symmetric

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

val <I : NonceTrait> SealedBox<out AuthCapability.Authenticated<*>, I, *>.authTag
    get() = (this as SealedBox.Authenticated<*, *>).authTag

val SealedBox<*, NonceTrait.Required, *>.nonce get() = (this as SealedBox.WithNonce<*, *>).nonce

/**
 * Represents symmetrically encrypted data in a structured manner.
 * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
 */
sealed interface SealedBox<A : AuthCapability<out K>, I : NonceTrait, K : KeyType> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>
    val encryptedData: ByteArray

    interface Authenticated<I : NonceTrait, K : KeyType> :
        SealedBox<AuthCapability.Authenticated<out K>, I, K> {
        val authTag: ByteArray
    }

    interface Unauthenticated<I : NonceTrait> :
        SealedBox<AuthCapability.Unauthenticated, I, KeyType.Integrated>

    /**
     * A sealed box without an IV/nonce.
     * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
     */
    sealed class WithoutNonce<A : AuthCapability<out K>, K : KeyType>(
        private val ciphertext: Ciphertext<A, NonceTrait.Without, SymmetricEncryptionAlgorithm<A, NonceTrait.Without, K>, K>
    ) : SealedBox<A, NonceTrait.Without, K> {

        override val algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Without, K> = ciphertext.algorithm
        override val encryptedData: ByteArray = ciphertext.encryptedData

        override fun toString(): String = "SealedBox.WithoutNonce(ciphertext=$ciphertext)"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithoutNonce<*, *>) return false

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
            WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated>(ciphertext),
            SealedBox.Unauthenticated<NonceTrait.Without>

        class Authenticated<K : KeyType>
        internal constructor(ciphertext: Ciphertext.Authenticated<AuthCapability.Authenticated<out K>, NonceTrait.Without, SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<out K>, NonceTrait.Without, K>, K>) :
            WithoutNonce<AuthCapability.Authenticated<out K>, K>(ciphertext),
            SealedBox.Authenticated<NonceTrait.Without, K> {
            override val authTag = ciphertext.authTag
        }
    }

    /**
     * A sealed box consisting of an [nonce] and the actual [ciphertext].
     * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
     */
    sealed class WithNonce<A : AuthCapability<out K>, K : KeyType>(
        val nonce: ByteArray,
        private val ciphertext: Ciphertext<A, NonceTrait.Required, SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>, K>
    ) : SealedBox<A, NonceTrait.Required, K> {

        override val algorithm: SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K> = ciphertext.algorithm
        override val encryptedData: ByteArray = ciphertext.encryptedData


        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithNonce<*, *>) return false

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
            WithNonce<AuthCapability.Unauthenticated, KeyType.Integrated>(nonce, ciphertext),
            SealedBox.Unauthenticated<NonceTrait.Required>

        class Authenticated<K : KeyType>
        internal constructor(
            nonce: ByteArray,
            ciphertext: Ciphertext.Authenticated<AuthCapability.Authenticated<out K>, NonceTrait.Required, SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<out K>, NonceTrait.Required, K>, K>
        ) :
            WithNonce<AuthCapability.Authenticated<out K>, K>(nonce, ciphertext),
            SealedBox.Authenticated<NonceTrait.Required, K> {
            override val authTag = ciphertext.authTag
        }
    }
}


/**
 * A generic ciphertext object, referencing the algorithm it was created by.
 */
sealed interface Ciphertext<A : AuthCapability<out K>, I : NonceTrait, E : SymmetricEncryptionAlgorithm<A, I, K>, K : KeyType> {
    val algorithm: E
    val encryptedData: ByteArray

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    class Authenticated<A : AuthCapability.Authenticated<out K>, I : NonceTrait, E : SymmetricEncryptionAlgorithm<A, I, K>, K : KeyType> internal constructor(
        override val algorithm: E,
        override val encryptedData: ByteArray,
        val authTag: ByteArray,
    ) : Ciphertext<A, I, E, K> {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, authTag=${
                authTag.toHexString(HexFormat.UpperCase)
            })"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Authenticated<*, *, *, *>) return false

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
        override val algorithm: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated>,
        override val encryptedData: ByteArray,
    ) : Ciphertext<AuthCapability.Unauthenticated, I,
            SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated>, KeyType.Integrated> {

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
fun <A : AuthCapability<out K>, K : KeyType, I : NonceTrait> SealedBox<A, I, out K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SealedBox.Authenticated<I, K>)
        returns(false) implies (this@isAuthenticated is SealedBox.Unauthenticated<I>)
    }
    return this.algorithm.authCapability is AuthCapability.Authenticated<*>
}

/**Use to smart-cast this sealed box*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<out K>, K : KeyType, I : NonceTrait> SealedBox<A, I, out K>.hasNonce(): Boolean {
    contract {
        returns(true) implies (this@hasNonce is SealedBox.WithNonce<A, K>)
        returns(false) implies (this@hasNonce is SealedBox.WithoutNonce<A, K>)
    }
    return algorithm.nonceTrait is NonceTrait.Required
}
