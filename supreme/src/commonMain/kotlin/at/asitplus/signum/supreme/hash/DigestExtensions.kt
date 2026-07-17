package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.Digest

internal expect suspend fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray
suspend fun Digest.digest(data: Sequence<ByteArray>) = doDigest(this, data)
@Suppress("NOTHING_TO_INLINE") suspend inline fun Digest.digest(bytes: ByteArray) = this.digest(sequenceOf(bytes))
