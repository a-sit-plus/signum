package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.digest.WellKnownDigest
import at.asitplus.signum.indispensable.jcaName
import java.security.MessageDigest

internal actual fun doDigest(digest: WellKnownDigest, data: Sequence<ByteArray>): ByteArray =
    MessageDigest.getInstance(digest.jcaName).apply {
        data.forEach { update(it) }
    }.digest()
