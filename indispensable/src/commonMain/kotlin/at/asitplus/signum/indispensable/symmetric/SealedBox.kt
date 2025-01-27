package at.asitplus.signum.indispensable.symmetric

import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract

val SealedBox<out AuthCapability.Authenticated<*>, *, *>.authTag
    get() = (this as SealedBox.Authenticated<*, *>).authTag
val SealedBox<out AuthCapability.Authenticated<*>, *, *>.authenticatedData
    get() = (this as SealedBox.Authenticated<*, *>).authenticatedData

val SealedBox<*, WithNonce.Yes, *>.nonce get() = (this as SealedBox.WithNonce<*, *>).nonce

/**
 * Represents symmetrically encrypted data. This is a separate class to more easily enforce type safety wrt. presence of
 * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
 */
sealed interface SealedBox<A : AuthCapability<K>, I : WithNonce, K : KeyType> {
    val algorithm: SymmetricEncryptionAlgorithm<A, I, K>
    val encryptedData: ByteArray

    interface Authenticated<I : at.asitplus.signum.indispensable.symmetric.WithNonce, K : KeyType> : SealedBox<AuthCapability.Authenticated<K>, I, K> {
        val authTag: ByteArray
        val authenticatedData: ByteArray?
    }

    interface Unauthenticated<I : at.asitplus.signum.indispensable.symmetric.WithNonce> : SealedBox<AuthCapability.Unauthenticated, I, KeyType.Integrated>

    /**
     * A sealed box without an IV/nonce.
     * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
     */
    sealed class WithoutNonce<A : AuthCapability<K>, K : KeyType>(
        private val ciphertext: Ciphertext<A, WithNonce.No, SymmetricEncryptionAlgorithm<A, WithNonce.No, K>, K>
    ) : SealedBox<A, WithNonce.No, K> {

        override val algorithm: SymmetricEncryptionAlgorithm<A, WithNonce.No, K> = ciphertext.algorithm
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
        internal constructor(ciphertext: Ciphertext.Unauthenticated<WithNonce.No>) :
            WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated>(ciphertext),
            SealedBox.Unauthenticated<WithNonce.No>

        class Authenticated<K : KeyType>
        internal constructor(ciphertext: Ciphertext.Authenticated<AuthCapability.Authenticated<K>, WithNonce.No, SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<K>, WithNonce.No, K>, K>) :
            WithoutNonce<AuthCapability.Authenticated<K>, K>(ciphertext), SealedBox.Authenticated<WithNonce.No, K> {
            override val authTag = ciphertext.authTag
            override val authenticatedData = ciphertext.authenticatedData
        }
    }

    /**
     * A sealed box consisting of an [nonce] and the actual [ciphertext].
     * Construct using [SymmetricEncryptionAlgorithm.sealedBoxFrom]
     */
    sealed class WithNonce<A : AuthCapability<K>, K : KeyType>(
        val nonce: ByteArray,
        private val ciphertext: Ciphertext<A, WithNonce.Yes, SymmetricEncryptionAlgorithm<A, WithNonce.Yes, K>, K>
    ) : SealedBox<A, WithNonce.Yes, K> {


        override val algorithm: SymmetricEncryptionAlgorithm<A, WithNonce.Yes, K> = ciphertext.algorithm
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
        internal constructor(nonce: ByteArray, ciphertext: Ciphertext.Unauthenticated<WithNonce.Yes>) :
            WithNonce<AuthCapability.Unauthenticated, KeyType.Integrated>(nonce, ciphertext),
            SealedBox.Unauthenticated<WithNonce.Yes>

        class Authenticated< K : KeyType>
        internal constructor(
            nonce: ByteArray,
            ciphertext: Ciphertext.Authenticated<AuthCapability.Authenticated<K>, WithNonce.Yes, SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<K>, WithNonce.Yes, K>, K>
        ) :
            WithNonce<AuthCapability.Authenticated<K>, K>(nonce, ciphertext),
            SealedBox.Authenticated<WithNonce.Yes, K> {
            override val authTag = ciphertext.authTag
            override val authenticatedData = ciphertext.authenticatedData
        }
    }
}


/**
 * A generic ciphertext object, referencing the algorithm it was created by.
 */
sealed interface Ciphertext<A : AuthCapability<K>, I : WithNonce, E : SymmetricEncryptionAlgorithm<A, I, K>, K : KeyType> {
    val algorithm: E
    val encryptedData: ByteArray

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    class Authenticated<A : AuthCapability.Authenticated<K>, I : WithNonce, E : SymmetricEncryptionAlgorithm<A, I, K>, K : KeyType> internal constructor(
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
    class Unauthenticated<I : WithNonce> internal constructor(
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
fun <A : AuthCapability<K>, K : KeyType, I : WithNonce> SealedBox<A, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SealedBox.Authenticated<I, K>)
        returns(false) implies (this@isAuthenticated is SealedBox.Unauthenticated<I>)
    }
    return this.algorithm.authCapability is AuthCapability.Authenticated<*>
}

/**Use to smart-cast this sealed box*/
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<K>, K : KeyType, I : WithNonce> SealedBox<A, I, out K>.hasNonce(): Boolean {
    contract {
        returns(true) implies (this@hasNonce is SealedBox.WithNonce<A, K>)
        returns(false) implies (this@hasNonce is SealedBox.WithoutNonce<A, K>)
    }
    return algorithm.withNonce is WithNonce.Yes
}