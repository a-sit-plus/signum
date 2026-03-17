package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.digest.WellKnownDigest

object SupremeDigestProvider : DigestOperationProvider {
    override fun getDigestOperator(digest: Digest): ((Sequence<ByteArray>) -> ByteArray)? {
        if (digest !is WellKnownDigest) return null
        return { doDigest(digest, it) }
    }
}

internal expect fun doDigest(digest: WellKnownDigest, data: Sequence<ByteArray>): ByteArray
