package at.asitplus.crypto.datatypes

import java.security.cert.CertificateFactory
import java.security.interfaces.ECPublicKey

actual object CryptoUtils {

    actual fun extractPublicKeyFromX509Cert(it: ByteArray): CryptoPublicKey? = kotlin.runCatching {
        val pubKey = CertificateFactory.getInstance("X.509").generateCertificate(it.inputStream()).publicKey
        if (pubKey is ECPublicKey) CryptoPublicKey.Ec.fromJcaKey(pubKey) else null
    }.getOrNull()

}