package at.asitplus.crypto.datatypes

expect object CryptoUtils {
    fun extractPublicKeyFromX509Cert(it: ByteArray): CryptoPublicKey?
}