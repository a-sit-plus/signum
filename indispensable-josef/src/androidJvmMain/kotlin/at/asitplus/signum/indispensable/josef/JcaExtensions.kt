package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.jcaName

val JweAlgorithm.jcaName: String?
    get() = when (this) {
        JweAlgorithm.ECDH_ES -> "ECDH"
        JweAlgorithm.RSA_OAEP_256, JweAlgorithm.RSA_OAEP_384, JweAlgorithm.RSA_OAEP_512 -> "RSA/ECB/OAEPPadding"
        is JweAlgorithm.Symmetric -> algorithm?.jcaName
        is JweAlgorithm.UNKNOWN -> null
    }