package at.asitplus.signum.indispensable

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration

/**
 * Umbrella interface encompassing _data integrity algorithms_:
 * * Message Authentication Codes ([MessageAuthenticationCode])
 * * Digital Signatures ([SignatureAlgorithm])
 */
sealed interface DataIntegrityAlgorithm : Enumerable {
    companion object : Enumeration<DataIntegrityAlgorithm> {
        override val entries: Iterable<DataIntegrityAlgorithm> by lazy { MessageAuthenticationCode.entries + SignatureAlgorithm.entries }
    }

}

interface SpecializedDataIntegrityAlgorithm {
    val algorithm: DataIntegrityAlgorithm
}
