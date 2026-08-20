@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.hash

import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.digest.DigestOperationProvider
import at.asitplus.signum.indispensable.digest.WellKnownDigest
import kotlinx.cinterop.CValuesRef
import kotlinx.cinterop.CVariable
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
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
        val _ = init(ctx.ptr)
        data.filter(ByteArray::isNotEmpty).forEach { data ->
            data.usePinned { val _ = update(ctx.ptr, it.addressOf(0), data.size.toUInt()) }
        }
        val output = UByteArray(outputLength)
        output.usePinned { val _ = finalize(it.addressOf(0), ctx.ptr) }
        return output.toByteArray()
    }
}

object SupremeIosDigestProvider : DigestOperationProvider {
    override suspend fun digest(digest: Digest, data: Sequence<ByteArray>) =
        when (digest as? WellKnownDigest) {
            WellKnownDigest.SHA1 -> digestTemplate(data, 20, ::CC_SHA1_Init, ::CC_SHA1_Update, ::CC_SHA1_Final)
            WellKnownDigest.SHA256 -> digestTemplate(data, 32, ::CC_SHA256_Init, ::CC_SHA256_Update, ::CC_SHA256_Final)
            WellKnownDigest.SHA384 -> digestTemplate(data, 48, ::CC_SHA384_Init, ::CC_SHA384_Update, ::CC_SHA384_Final)
            WellKnownDigest.SHA512 -> digestTemplate(data, 64, ::CC_SHA512_Init, ::CC_SHA512_Update, ::CC_SHA512_Final)
            null -> null
        }
}
