package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.Digest

internal expect fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray
fun Digest.digest(data: Sequence<ByteArray>) = doDigest(this, data)
@Suppress("NOTHING_TO_INLINE") inline fun Digest.digest(bytes: ByteArray) = this.digest(sequenceOf(bytes))
