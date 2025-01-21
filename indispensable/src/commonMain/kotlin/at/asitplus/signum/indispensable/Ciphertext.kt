package at.asitplus.signum.indispensable

/**
 * A generic ciphertext object, referencing the algorithm it was created by and an IV, if any.
 */
sealed class Ciphertext<out A : AuthTrait, T : SymmetricEncryptionAlgorithm<out A>>(
    open val algorithm: T,
    val encryptedData: ByteArray,
    val iv: ByteArray?
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Ciphertext<*, *>) return false

        if (algorithm != other.algorithm) return false
        if (!encryptedData.contentEquals(other.encryptedData)) return false
        if (!iv.contentEquals(other.iv)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = algorithm.hashCode()
        result = 31 * result + encryptedData.contentHashCode()
        result = 31 * result + (iv?.contentHashCode() ?: 0)
        return result
    }

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [authenticatedData] (_Additional Authenticated Data_)
     */
    open class Authenticated(
        algorithm: SymmetricEncryptionAlgorithm.Authenticated<*>,
        encryptedData: ByteArray,
        iv: ByteArray?,
        val authTag: ByteArray,
        val authenticatedData: ByteArray?
    ) : Ciphertext<AuthTrait.Authenticated, SymmetricEncryptionAlgorithm.Authenticated<*>>(algorithm, encryptedData, iv) {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, iv=${
                iv?.toHexString(
                    HexFormat.UpperCase
                )
            }, authTag=${
                authTag.toHexString(HexFormat.UpperCase)
            }, aad=${authenticatedData?.toHexString(HexFormat.UpperCase)})"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Authenticated) return false
            if (!super.equals(other)) return false

            if (!authTag.contentEquals(other.authTag)) return false
            if (!authenticatedData.contentEquals(other.authenticatedData)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = super.hashCode()
            result = 31 * result + authTag.contentHashCode()
            result = 31 * result + (authenticatedData?.contentHashCode() ?: 0)
            return result
        }

        class WithDedicatedMac(
            override val algorithm: SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac,
            encryptedData: ByteArray,
            iv: ByteArray?,
            authTag: ByteArray,
            aad: ByteArray?
        ) : Authenticated(algorithm, encryptedData, iv, authTag, aad)
    }

    /**
     * An Unauthenticated ciphertext, most probably containing an [iv], but not guaranteed to.
     */
    class Unauthenticated(
        algorithm: SymmetricEncryptionAlgorithm.Unauthenticated,
        encryptedData: ByteArray,
        iv: ByteArray?
    ) : Ciphertext<AuthTrait.Unauthenticated, SymmetricEncryptionAlgorithm.Unauthenticated>(
        algorithm,
        encryptedData,
        iv
    ) {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            "$algorithm Unauthenticated Ciphertext(encryptedData=${encryptedData.toHexString(HexFormat.UpperCase)}, iv=${
                iv?.toHexString(
                    HexFormat.UpperCase
                )
            })"

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Unauthenticated) return false
            if (!super.equals(other)) return false
            return true
        }

        override fun hashCode(): Int {
            return super.hashCode()
        }
    }
}