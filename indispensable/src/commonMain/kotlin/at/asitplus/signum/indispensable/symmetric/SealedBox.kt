package at.asitplus.signum.indispensable.symmetric

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

val SealedBox<out AuthType.Authenticated<*>, *, *>.authTag
    get() = (this as SealedBox.Authenticated<*, *>).authTag
val SealedBox<out AuthType.Authenticated<*>, *, *>.authenticatedData
    get() = (this as SealedBox.Authenticated<*, *>).authenticatedData

val SealedBox<*, Nonce.Required, *>.nonce get() = (this as SealedBox.WithNonce<*, *>).nonce

/**
 * Represents symmetrically encrypted data. This is a separate class to more easily enforce type safety wrt. presence of
 * Construct using [SymmetricEncryptionAlgorithm.sealedBox]
 */
sealed interface SealedBox<A : AuthType<K>, I : Nonce, K : KeyType> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>
    val encryptedData: ByteArray

    interface Authenticated<I : Nonce, K : KeyType> : SealedBox<AuthType.Authenticated<K>, I, K> {
        val authTag: ByteArray
        val authenticatedData: ByteArray?
    }

    interface Unauthenticated<I : Nonce> : SealedBox<AuthType.Unauthenticated, I, KeyType.Integrated>

    /**
     * A sealed box without an IV/nonce.
     * The possibility to implement key wrapping and electronic codebook mode of operation for block ciphers come to mind.
     * Construct using [SymmetricEncryptionAlgorithm.sealedBox]
     */
    sealed class WithoutNonce<A : AuthType<K>, K : KeyType>(
        private val ciphertext: Ciphertext<A, Nonce.Without, SymmetricEncryptionAlgorithm<A, Nonce.Without, K>, K>
    ) : SealedBox<A, Nonce.Without, K> {

        override val algorithm: SymmetricEncryptionAlgorithm<A, Nonce.Without, K> = ciphertext.algorithm
        override val encryptedData: ByteArray = ciphertext.encryptedData

        override fun toString(): String = "SealedBox.WithoutNonce(ciphertext=$ciphertext)"
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithoutNonce<*, *>) return false

            if (ciphertext != other.ciphertext) return false
            if (algorithm != other.algorithm) return false
            if (!encryptedData.contentEquals(other.encryptedData)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = ciphertext.hashCode()
            result = 31 * result + algorithm.hashCode()
            result = 31 * result + encryptedData.contentHashCode()
            return result
        }

        class Unauthenticated
        internal constructor(ciphertext: Ciphertext.Unauthenticated<Nonce.Without>) :
            WithoutNonce<AuthType.Unauthenticated, KeyType.Integrated>(ciphertext),
            SealedBox.Unauthenticated<Nonce.Without>

        class Authenticated<K : KeyType>
        internal constructor(ciphertext: Ciphertext.Authenticated<AuthType.Authenticated<K>, Nonce.Without, SymmetricEncryptionAlgorithm<AuthType.Authenticated<K>, Nonce.Without, K>, K>) :
            WithoutNonce<AuthType.Authenticated<K>, K>(ciphertext), SealedBox.Authenticated<Nonce.Without, K> {
            override val authTag = ciphertext.authTag
            override val authenticatedData = ciphertext.authenticatedData
        }
    }

    /**
     * A sealed box consisting of an [nonce] and the actual [ciphertext].
     * Construct using [SymmetricEncryptionAlgorithm.sealedBox]
     */
    sealed class WithNonce<A : AuthType<K>, K : KeyType>(
        val nonce: ByteArray,
        private val ciphertext: Ciphertext<A, Nonce.Required, SymmetricEncryptionAlgorithm<A, Nonce.Required, K>, K>
    ) : SealedBox<A, Nonce.Required, K> {


        override val algorithm: SymmetricEncryptionAlgorithm<A, Nonce.Required, K> = ciphertext.algorithm
        override val encryptedData: ByteArray = ciphertext.encryptedData


        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithNonce<*, *>) return false

            if (!nonce.contentEquals(other.nonce)) return false
            if (ciphertext != other.ciphertext) return false
            if (algorithm != other.algorithm) return false
            if (!encryptedData.contentEquals(other.encryptedData)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = nonce.contentHashCode()
            result = 31 * result + ciphertext.hashCode()
            result = 31 * result + algorithm.hashCode()
            result = 31 * result + encryptedData.contentHashCode()
            return result
        }

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "SealedBox.WithNonce(nonce=${nonce.toHexString(HexFormat.UpperCase)}, ciphertext=$ciphertext)"

        class Unauthenticated
        internal constructor(nonce: ByteArray, ciphertext: Ciphertext.Unauthenticated<Nonce.Required>) :
            WithNonce<AuthType.Unauthenticated, KeyType.Integrated>(nonce, ciphertext),
            SealedBox.Unauthenticated<Nonce.Required>

        class Authenticated< K : KeyType>
        internal constructor(
            nonce: ByteArray,
            ciphertext: Ciphertext.Authenticated<AuthType.Authenticated<K>, Nonce.Required, SymmetricEncryptionAlgorithm<AuthType.Authenticated<K>, Nonce.Required, K>, K>
        ) :
            WithNonce<AuthType.Authenticated<K>, K>(nonce, ciphertext),
            SealedBox.Authenticated<Nonce.Required, K> {
            override val authTag = ciphertext.authTag
            override val authenticatedData = ciphertext.authenticatedData
        }
    }
}


/**
 * A generic ciphertext object, referencing the algorithm it was created by.
 */
internal sealed interface Ciphertext<A : AuthType<K>, I : Nonce, E : SymmetricEncryptionAlgorithm<A, I, K>, K : KeyType> {
    val algorithm: E
    val encryptedData: ByteArray

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    class Authenticated<A : AuthType.Authenticated<K>, I : Nonce, E : SymmetricEncryptionAlgorithm<A, I, K>, K : KeyType>(
        override val algorithm: E,
        override val encryptedData: ByteArray,
        val authTag: ByteArray,
        val authenticatedData: ByteArray?
    ) : Ciphertext<A, I, E, K> {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, authTag=${
                authTag.toHexString(HexFormat.UpperCase)
            }, aad=${authenticatedData?.toHexString(HexFormat.UpperCase)})"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Authenticated<*, *, *, *>) return false

            if (algorithm != other.algorithm) return false
            if (!encryptedData.contentEquals(other.encryptedData)) return false
            if (!authTag.contentEquals(other.authTag)) return false
            if (!authenticatedData.contentEquals(other.authenticatedData)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = algorithm.hashCode()
            result = 31 * result + encryptedData.contentHashCode()
            result = 31 * result + authTag.contentHashCode()
            result = 31 * result + (authenticatedData?.contentHashCode() ?: 0)
            return result
        }

    }

    /**
     * An Unauthenticated ciphertext
     */
    class Unauthenticated<I : Nonce>(
        override val algorithm: SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, I, KeyType.Integrated>,
        override val encryptedData: ByteArray,
    ) : Ciphertext<AuthType.Unauthenticated, I,
            SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, I, KeyType.Integrated>, KeyType.Integrated> {

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

/**Use to smart-cast this algorithm*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SealedBox<A, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SealedBox.Authenticated<I, K>)
        returns(false) implies (this@isAuthenticated is SealedBox.Unauthenticated<I>)
    }
    return this.algorithm.authCapability is AuthType.Authenticated<*>
}

/**Use to smart-cast this algorithm*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SealedBox<A, I, out K>.hasNonce(): Boolean {
    contract {
        returns(true) implies (this@hasNonce is SealedBox.WithNonce<A, K>)
        returns(false) implies (this@hasNonce is SealedBox.WithoutNonce<A, K>)
    }
    return algorithm.nonce is Nonce.Required
}