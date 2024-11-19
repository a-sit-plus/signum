package at.asitplus.signum.indispensable

open class Ciphertext(val algorithm: EncryptionAlgorithm, val encryptedData: ByteArray, val iv: ByteArray? = null) {

    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String =
        "$algorithm Ciphertext(encryptedData=${encryptedData.toHexString(HexFormat.UpperCase)}, iv=${iv?.toHexString(HexFormat.UpperCase)})"

    class Authenticated(algorithm: EncryptionAlgorithm, encryptedData: ByteArray, iv: ByteArray? = null, val authTag: ByteArray, val aad: ByteArray?) :
        Ciphertext(algorithm, encryptedData, iv) {

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String =
            " $algorithm Authenticated Ciphertext(encryptedData=${this.encryptedData.toHexString(HexFormat.UpperCase)}, iv=${iv?.toHexString(HexFormat.UpperCase)}, authTag=${
                authTag.toHexString(HexFormat.UpperCase)
            }, aad=${aad?.toHexString(HexFormat.UpperCase)})"
    }
}