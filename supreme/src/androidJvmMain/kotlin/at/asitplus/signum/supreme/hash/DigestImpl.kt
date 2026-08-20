package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.jcaName
import java.security.MessageDigest

object SupremeJVMDigestProvider : DigestOperationProvider {
    override suspend fun digest(digest: Digest, data: Sequence<ByteArray>): ByteArray? {
        if (digest !is WellKnownDigest) return null
        return MessageDigest.getInstance(digest.jcaName).apply {
            data.forEach { update(it) }
        }.digest()
    }
}
