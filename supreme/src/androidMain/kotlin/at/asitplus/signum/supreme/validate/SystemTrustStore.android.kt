package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.toKmpCertificate
import java.security.KeyStore
import java.security.cert.X509Certificate

actual val SystemTrustStore: Set<TrustAnchor> = KeyStore.getInstance("AndroidCAStore").let {
    it.load(null)
   val  aliases = it.aliases()
    val trustAnchors = mutableSetOf<TrustAnchor>()
    while (aliases.hasMoreElements()) {
      val  alias = aliases.nextElement();
        val cert = it.getCertificate(alias);
        if (cert is X509Certificate) {
            cert.toKmpCertificate().onSuccess { trustAnchors.add(TrustAnchor.CertificateAnchor(it)) }
        }
    }
    trustAnchors
}
