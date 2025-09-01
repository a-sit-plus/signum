package at.asitplus.signum.indispensable

/**
 * Umbrella interface encompassing _data integrity algorithms_:
 * * Message Authentication Codes ([MessageAuthenticationCode])
 * * Digital Signatures ([SignatureAlgorithm])
 */
sealed interface DataIntegrityAlgorithm {
    companion object {
        val entries: Set<DataIntegrityAlgorithm> by lazy { MessageAuthenticationCode.entries.toSet() + SignatureAlgorithm.entries }
    }

}

interface SpecializedDataIntegrityAlgorithm {
    val algorithm: DataIntegrityAlgorithm
}
