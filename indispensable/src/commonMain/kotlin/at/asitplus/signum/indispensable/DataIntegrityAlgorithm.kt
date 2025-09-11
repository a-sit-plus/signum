package at.asitplus.signum.indispensable

import at.asitplus.signum.internals.Enumerable
import at.asitplus.signum.internals.Enumeration

/**
 * Umbrella interface encompassing _data integrity algorithms_:
 * * Message Authentication Codes ([MessageAuthenticationCode])
 * * Digital Signatures ([SignatureAlgorithm])
 */
sealed interface DataIntegrityAlgorithm : Enumerable {
    companion object : Enumeration<DataIntegrityAlgorithm> {
        override val entries: Set<DataIntegrityAlgorithm> by lazy { MessageAuthenticationCode.entries.toSet() + SignatureAlgorithm.entries }
    }

}

interface SpecializedDataIntegrityAlgorithm {
    val algorithm: DataIntegrityAlgorithm
}
