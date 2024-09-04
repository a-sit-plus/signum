@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.Digest
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.CVariable
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.objcPtr
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_LONG
import platform.CoreCrypto.CC_SHA1_Final
import platform.CoreCrypto.CC_SHA1_Init
import platform.CoreCrypto.CC_SHA1_Update
import platform.CoreCrypto.CC_SHA256_Final
import platform.CoreCrypto.CC_SHA256_Init
import platform.CoreCrypto.CC_SHA256_Update
import platform.CoreCrypto.CC_SHA384_Final
import platform.CoreCrypto.CC_SHA384_Init
import platform.CoreCrypto.CC_SHA384_Update
import platform.CoreCrypto.CC_SHA512_Final
import platform.CoreCrypto.CC_SHA512_Init
import platform.CoreCrypto.CC_SHA512_Update

private inline fun <reified T: CVariable> digestTemplate(
    data: Sequence<ByteArray>,
    outputLength: Int,
    init: (CValuesRef<T>)->Int,
    update: (CValuesRef<T>, CValuesRef<*>?, CC_LONG)->Int,
    finalize: (CValuesRef<UByteVar>, CValuesRef<T>)->Int
): ByteArray {
    memScoped {
        val ctx = alloc<T>()
        init(ctx.ptr)
        data.forEach { a ->
            if (a.isNotEmpty())
                a.usePinned { update(ctx.ptr, it.addressOf(0), a.size.toUInt()) }
            else
                a.usePinned { update(ctx.ptr, null, a.size.toUInt()) }
        }
        val output = UByteArray(outputLength)
        output.usePinned { finalize(it.addressOf(0), ctx.ptr) }
        return output.toByteArray()
    }
}
internal actual fun doDigest(digest: Digest, data: Sequence<ByteArray>): ByteArray = when(digest) {
    Digest.SHA1 -> digestTemplate(data, digest.outputLength.bytes.toInt(), ::CC_SHA1_Init, ::CC_SHA1_Update, ::CC_SHA1_Final)
    Digest.SHA256 -> digestTemplate(data, digest.outputLength.bytes.toInt(), ::CC_SHA256_Init, ::CC_SHA256_Update, ::CC_SHA256_Final)
    Digest.SHA384 -> digestTemplate(data, digest.outputLength.bytes.toInt(), ::CC_SHA384_Init, ::CC_SHA384_Update, ::CC_SHA384_Final)
    Digest.SHA512 -> digestTemplate(data, digest.outputLength.bytes.toInt(), ::CC_SHA512_Init, ::CC_SHA512_Update, ::CC_SHA512_Final)
}
