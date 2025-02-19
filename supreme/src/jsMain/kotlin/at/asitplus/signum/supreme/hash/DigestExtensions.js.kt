package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.Digest
import dev.whyoleg.cryptography.providers.webcrypto.internal.getSubtleCrypto
import kotlinx.browser.window
import kotlinx.coroutines.asDeferred
import org.khronos.webgl.Int8Array

actual suspend fun doDigest(
    digest: Digest,
    data: Sequence<ByteArray>
): ByteArray  {
    val crypto = getSubtleCrypto()
    val name = when(digest) {
        Digest.SHA1 -> "SHA-1"
        Digest.SHA256 -> "SHA-256"
        Digest.SHA384 -> "SHA-384"
        Digest.SHA512 -> "SHA-512"
    }
    return crypto.digest(name,data.first()).asDeferred().await().run { Int8Array(this).unsafeCast<ByteArray>() }
}

