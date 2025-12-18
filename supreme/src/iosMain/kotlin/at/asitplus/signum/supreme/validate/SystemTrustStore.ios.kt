package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.X509Certificate

actual val SystemTrustStore: Set<TrustAnchor> =
    appleRoots.map { TrustAnchor.Certificate(X509Certificate.decodeFromDer(it.hexToByteArray())) }.toSet()