package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.jcaName
import java.security.MessageDigest

internal actual fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray =
    MessageDigest.getInstance(digest.jcaName).apply {
        data.forEach { update(it) }
    }.digest()
