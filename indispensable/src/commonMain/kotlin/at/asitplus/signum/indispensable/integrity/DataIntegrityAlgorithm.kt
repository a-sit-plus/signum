package at.asitplus.signum.indispensable.integrity

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration

/**
 * Umbrella interface encompassing _data integrity algorithms_:
 * * Message Authentication Codes ([MessageAuthenticationCode])
 * * Digital Signatures ([SignatureAlgorithm])
 */
sealed interface DataIntegrityAlgorithm

interface SpecializedDataIntegrityAlgorithm {
    val algorithm: DataIntegrityAlgorithm
}
