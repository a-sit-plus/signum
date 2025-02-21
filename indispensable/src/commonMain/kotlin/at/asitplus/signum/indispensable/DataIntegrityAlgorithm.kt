package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode

/**
 * Umbrella interface encompassing _data integrity algorithms_:
 * * Message Authentication Codes ([MessageAuthenticationCode])
 * * Digital Signatures ([SignatureAlgorithm])
 */
interface DataIntegrityAlgorithm {
    companion object {
        val entries: Iterable<DataIntegrityAlgorithm> = MessageAuthenticationCode.entries + SignatureAlgorithm.entries
    }

}