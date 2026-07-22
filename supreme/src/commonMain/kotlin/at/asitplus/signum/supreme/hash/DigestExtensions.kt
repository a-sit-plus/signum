package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.digest.WellKnownDigest

object SupremeDigestProvider : DigestOperationProvider {
    override suspend fun digest(digest: Digest, data: Sequence<ByteArray>) : ByteArray? {
        if (digest !is WellKnownDigest) return null
        return doDigest(digest, data)
    }
}

internal expect suspend fun doDigest(digest: WellKnownDigest, data: Sequence<ByteArray>): ByteArray
