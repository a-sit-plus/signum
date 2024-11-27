package at.asitplus.signum.indispensable

/**
 * A generic ciphertext object, referencing the algorithm it was created by and an IV, if any.
 */
sealed class Ciphertext<out A: AuthTrait,T: EncryptionAlgorithm<out A>>(val algorithm: T, val encryptedData: ByteArray, val iv: ByteArray? = null) {
    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [aad] (_Additional Authenticated Data_)
     */
    class Authenticated(algorithm: EncryptionAlgorithm.Authenticated, encryptedData: ByteArray, iv: ByteArray? = null, val authTag: ByteArray, val aad: ByteArray?) :
        Ciphertext<AuthTrait.Authenticated, EncryptionAlgorithm.Authenticated>(algorithm, encryptedData, iv) {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            " $algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, iv=${iv?.toHexString(HexFormat.UpperCase)}, authTag=${
                authTag.toHexString(HexFormat.UpperCase)
            }, aad=${aad?.toHexString(HexFormat.UpperCase)})"
    }

    /**
     * An authenticated ciphertext, i.e. containing an [authTag], and, optionally [aad] (_Additional Authenticated Data_)
     */
    class Unauthenticated(algorithm: EncryptionAlgorithm.Unauthenticated, encryptedData: ByteArray, iv: ByteArray? = null) :
        Ciphertext<AuthTrait.Unauthenticated, EncryptionAlgorithm.Unauthenticated>(algorithm, encryptedData, iv) {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            " $algorithm Unauthenticated Ciphertext(encryptedData=${encryptedData.toHexString(HexFormat.UpperCase)}, iv=${iv?.toHexString(HexFormat.UpperCase)})"
    }
}