package at.asitplus.crypto.datatypes.jws

val JweEncryption.jcaName
    get() = when (this) {
        JweEncryption.A256GCM -> "AES/GCM/NoPadding"
    }

val JweEncryption.jcaKeySpecName
    get() = when (this) {
        JweEncryption.A256GCM -> "AES"
    }

val JweAlgorithm.jcaName
    get() = when (this) {
        JweAlgorithm.ECDH_ES -> "ECDH"
    }