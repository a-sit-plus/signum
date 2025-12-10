package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.toKmpCertificate
import java.security.KeyStore
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

actual val SystemTrustStore: Set<TrustAnchor> = TrustManagerFactory.getInstance(
    TrustManagerFactory.getDefaultAlgorithm()
).let {
    it.init(null as KeyStore?) // ← tells JSSE: load the default trust store

    var tm: X509TrustManager? = null
    for (t in it.trustManagers) {
        if (t is X509TrustManager) {
            tm = t
            break
        }
    }
    val trustAnchors = mutableSetOf<TrustAnchor>()
    tm?.acceptedIssuers?.forEach {
        it.toKmpCertificate().onSuccess {
            trustAnchors += TrustAnchor.CertificateAnchor(it)
        }
    }
    trustAnchors
}

