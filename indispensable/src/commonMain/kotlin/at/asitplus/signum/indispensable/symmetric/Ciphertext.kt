package at.asitplus.signum.indispensable.symmetric

import kotlin.jvm.JvmName


val <A : CipherKind.Authenticated, I : Nonce> SealedBox<out A, out I, SymmetricEncryptionAlgorithm<A, I>>.authTag: ByteArray get() = (ciphertext as Ciphertext.Authenticated<A, SymmetricEncryptionAlgorithm<A, I>>).authTag
val <A : CipherKind.Authenticated, I : Nonce> SealedBox<out A, out I, SymmetricEncryptionAlgorithm<A, I>>.authenticatedData: ByteArray? get() = (ciphertext as Ciphertext.Authenticated<A, SymmetricEncryptionAlgorithm<A, I>>).authenticatedData
val SealedBox<*, Nonce.Required, *>.nonce: ByteArray get() = (this as SealedBox.WithNonce<*, *>).nonce

/**
 * Represents symmetrically encrypted data. This is a separate class to more easily enforce type safety wrt. presence of
 * an IV.
 * The contained [ciphertext]'s `algorithm` must match the generic type information of a `SealedBox`.
 * Construct using [SymmetricEncryptionAlgorithm.sealedBox]
 */
sealed class SealedBox<A : CipherKind, I : Nonce, E : SymmetricEncryptionAlgorithm<A, I>>(
    internal val ciphertext: Ciphertext<A, E>
) {
    val algorithm: E get()= ciphertext.algorithm
    val encryptedData: ByteArray get() = ciphertext.encryptedData
    val cipherKind: A = algorithm.cipher

    /**
     * A sealed box without an IV. Key wrapping and electronic codebook block cipher mode of operation come to mind.
     *  Construct using [SymmetricEncryptionAlgorithm.sealedBox]
     */
    class WithoutNonce<A : CipherKind, E : SymmetricEncryptionAlgorithm<A, Nonce.Without>> internal constructor(ciphertext: Ciphertext<A, E>) :
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
    class WithNonce<A : CipherKind, E : SymmetricEncryptionAlgorithm<A, Nonce.Required>> internal constructor(
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
 * A generic ciphertext object, referencing the algorithm it was created by and an IV, if any.
 */
internal sealed interface Ciphertext<A : CipherKind, E : SymmetricEncryptionAlgorithm<A, *>> {
    val algorithm: E
    val encryptedData: ByteArray

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    class Authenticated<A : CipherKind.Authenticated, E : SymmetricEncryptionAlgorithm<A, *>>(
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
        override val algorithm: SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>,
        override val encryptedData: ByteArray,
    ) : Ciphertext<CipherKind.Unauthenticated,
            SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, *>> {

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



@JvmName("sealedBoxUnauthedWithNonce")
fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Required>.sealedBox(
    nonce: ByteArray,
    encryptedData: ByteArray
) = SealedBox.WithNonce<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Required>>(
    nonce,
    Ciphertext.Unauthenticated(
        this,
        encryptedData
    ) as Ciphertext<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Required>>
)

fun SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Without>.sealedBox(
    encryptedData: ByteArray
) =
    SealedBox.WithoutNonce<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Without>>(
        Ciphertext.Unauthenticated(
            this,
            encryptedData
        ) as Ciphertext<CipherKind.Unauthenticated, SymmetricEncryptionAlgorithm<CipherKind.Unauthenticated, Nonce.Without>>
    )

@JvmName("sealedBoxAuthenticatedDedicated")
fun SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>.sealedBox(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = (this as SymmetricEncryptionAlgorithm<CipherKind.Authenticated, Nonce.Required>).sealedBox(
    nonce,
    encryptedData,
    authTag,
    authenticatedData
) as SealedBox.WithNonce<CipherKind.Authenticated.WithDedicatedMac<*, Nonce.Required>, SymmetricEncryptionAlgorithm<CipherKind.Authenticated.WithDedicatedMac<*, Nonce.Required>, Nonce.Required>>

@JvmName("sealedBoxAuthenticated")
fun <A : CipherKind.Authenticated> SymmetricEncryptionAlgorithm<A, Nonce.Required>.sealedBox(
    nonce: ByteArray,
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = SealedBox.WithNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Required>>(
    nonce,
    authenticatedCipherText(encryptedData, authTag, authenticatedData)
)

@JvmName("sealedBoxAuthenticated")
fun <A : CipherKind.Authenticated> SymmetricEncryptionAlgorithm<A, Nonce.Without>.sealedBox(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = SealedBox.WithoutNonce<A, SymmetricEncryptionAlgorithm<A, Nonce.Without>>(
    authenticatedCipherText(encryptedData, authTag, authenticatedData)
)


private inline fun <A : CipherKind.Authenticated, reified I : Nonce> SymmetricEncryptionAlgorithm<A, I>.authenticatedCipherText(
    encryptedData: ByteArray,
    authTag: ByteArray,
    authenticatedData: ByteArray? = null
) = Ciphertext.Authenticated<A, SymmetricEncryptionAlgorithm<A, I>>(
    this,
    encryptedData,
    authTag,
    authenticatedData
)