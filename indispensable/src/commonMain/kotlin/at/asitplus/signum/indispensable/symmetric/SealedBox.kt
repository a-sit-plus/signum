package at.asitplus.signum.indispensable.symmetric

import kotlin.jvm.JvmName


val <A : AECapability.Authenticated, I : Nonce> SealedBox<out A, out I, SymmetricEncryptionAlgorithm<A, I>>.authTag: ByteArray get() = (ciphertext as Ciphertext.Authenticated<A, SymmetricEncryptionAlgorithm<A, I>>).authTag
val <A : AECapability.Authenticated, I : Nonce> SealedBox<out A, out I, SymmetricEncryptionAlgorithm<A, I>>.authenticatedData: ByteArray? get() = (ciphertext as Ciphertext.Authenticated<A, SymmetricEncryptionAlgorithm<A, I>>).authenticatedData
val SealedBox<*, Nonce.Required, *>.nonce: ByteArray get() = (this as SealedBox.WithNonce<*, *>).nonce

/**
 * Represents symmetrically encrypted data. This is a separate class to more easily enforce type safety wrt. presence of
 * Construct using [SymmetricEncryptionAlgorithm.sealedBox]
 */
sealed class SealedBox<A : AECapability, I : Nonce, E : SymmetricEncryptionAlgorithm<A, I>>(
    internal val ciphertext: Ciphertext<A, E>
) {
    val algorithm: E get()= ciphertext.algorithm
    val encryptedData: ByteArray get() = ciphertext.encryptedData
    val cipherKind: A = algorithm.cipher

    /**
     * A sealed box without an IV/nonce.
     * The possibility to implement key wrapping and electronic codebook mode of operation for block ciphers come to mind.
     * Construct using [SymmetricEncryptionAlgorithm.sealedBox]
     */
    class WithoutNonce<A : AECapability, E : SymmetricEncryptionAlgorithm<A, Nonce.Without>> internal constructor(ciphertext: Ciphertext<A, E>) :
        SealedBox<A, Nonce.Without, E>(ciphertext) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithoutNonce<*, *>) return false
            if (!super.equals(other)) return false
            return true
        }

        override fun hashCode(): Int {
            return super.hashCode()
        }

        override fun toString(): String = "SealedBox.WithoutNonce(ciphertext=$ciphertext)"
    }

    /**
     * A sealed box consisting of an [nonce] and the actual [ciphertext].
     * Construct using [SymmetricEncryptionAlgorithm.sealedBox]
     */
    class WithNonce<A : AECapability, E : SymmetricEncryptionAlgorithm<A, Nonce.Required>> internal constructor(
        internal val nonce: ByteArray,
        ciphertext: Ciphertext<A, E>
    ) : SealedBox<A, Nonce.Required, E>(ciphertext) {

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is WithNonce<*, *>) return false
            if (!super.equals(other)) return false
            if (!this@WithNonce.nonce.contentEquals(other.nonce)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = super.hashCode()
            result = 31 * result + nonce.contentHashCode()
            return result
        }

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "SealedBox.WithNonce(nonce=${nonce.toHexString(HexFormat.UpperCase)}, ciphertext=$ciphertext)"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SealedBox<*, *, *>) return false
        if (ciphertext != other.ciphertext) return false

        return true
    }

    override fun hashCode(): Int {
        return ciphertext.hashCode()
    }
}


/**
 * A generic ciphertext object, referencing the algorithm it was created by.
 */
internal sealed interface Ciphertext<A : AECapability, E : SymmetricEncryptionAlgorithm<A, *>> {
    val algorithm: E
    val encryptedData: ByteArray

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    class Authenticated<A : AECapability.Authenticated, E : SymmetricEncryptionAlgorithm<A, *>>(
        override val algorithm: E,
        override val encryptedData: ByteArray,
        val authTag: ByteArray,
        val authenticatedData: ByteArray?
    ) : Ciphertext<A, E> {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, authTag=${
                authTag.toHexString(HexFormat.UpperCase)
            }, aad=${authenticatedData?.toHexString(HexFormat.UpperCase)})"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Authenticated<*, *>) return false
            if (algorithm != other.algorithm) return false
            if (!encryptedData.contentEquals(other.encryptedData)) return false
            if (!authTag.contentEquals(other.authTag)) return false
            if (!authenticatedData.contentEquals(other.authenticatedData)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = super.hashCode()
            result = 31 * result + algorithm.hashCode()
            result = 31 * result + encryptedData.contentHashCode()
            result = 31 * result + authTag.contentHashCode()
            result = 31 * result + (authenticatedData?.contentHashCode() ?: 0)
            return result
        }
    }

    /**
     * An Unauthenticated ciphertext
     */
    class Unauthenticated(
        override val algorithm: SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>,
        override val encryptedData: ByteArray,
    ) : Ciphertext<AECapability.Unauthenticated,
            SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, *>> {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Unauthenticated Ciphertext(encryptedData=${
                encryptedData.toHexString(HexFormat.UpperCase)
            })"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Unauthenticated) return false
            if (algorithm != other.algorithm) return false
            if (!encryptedData.contentEquals(other.encryptedData)) return false
            return true
        }

        override fun hashCode(): Int {
            return super.hashCode()
        }
    }
}


/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] is was created for.
 * Use this function to load external encrypted data for decryption.
 */
@JvmName("sealedBoxUnauthedWithNonce")
fun SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Required>.sealedBox(
    nonce: ByteArray,
    encryptedData: ByteArray
) = SealedBox.WithNonce<AECapability.Unauthenticated, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Required>>(
    nonce,
    Ciphertext.Unauthenticated(
        this,
        encryptedData
    ) as Ciphertext<AECapability.Unauthenticated, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Required>>
)

/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] is was created for.
 * Use this function to load external encrypted data for decryption.
 */
fun SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Without>.sealedBox(
    encryptedData: ByteArray
) =
    SealedBox.WithoutNonce<AECapability.Unauthenticated, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Without>>(
        Ciphertext.Unauthenticated(
            this,
            encryptedData
        ) as Ciphertext<AECapability.Unauthenticated, SymmetricEncryptionAlgorithm<AECapability.Unauthenticated, Nonce.Without>>
    )

/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] is was created for.
 * Use this function to load external encrypted data for decryption.
 */
@JvmName("sealedBoxAuthenticatedDedicated")
fun SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>.sealedBox(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = (this as SymmetricEncryptionAlgorithm<AECapability.Authenticated, Nonce.Required>).sealedBox(
    nonce,
    encryptedData,
    authTag,
    authenticatedData
) as SealedBox.WithNonce<AECapability.Authenticated.WithDedicatedMac<*, Nonce.Required>, SymmetricEncryptionAlgorithm<AECapability.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>>

/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] is was created for.
 * Use this function to load external encrypted data for decryption.
 */
@JvmName("sealedBoxAuthenticated")
fun <A : AECapability.Authenticated> SymmetricEncryptionAlgorithm<A, Nonce.Required>.sealedBox(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>(
    nonce,
    authenticatedCipherText(encryptedData, authTag, authenticatedData)
)

/**
 * Creates a [SealedBox] matching the characteristics of the [SymmetricEncryptionAlgorithm] is was created for.
 * Use this function to load external encrypted data for decryption.
 */
@JvmName("sealedBoxAuthenticated")
fun <A : AECapability.Authenticated> SymmetricEncryptionAlgorithm<A, Nonce.Without>.sealedBox(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = SealedBox.WithoutNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Without>>(
    authenticatedCipherText(encryptedData, authTag, authenticatedData)
)


private inline fun <A : AECapability.Authenticated, reified I : Nonce> SymmetricEncryptionAlgorithm<A, I>.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = Ciphertext.Authenticated<A, SymmetricEncryptionAlgorithm<A, I>>(
    this,
    encryptedData,
    authTag,
    authenticatedData
)