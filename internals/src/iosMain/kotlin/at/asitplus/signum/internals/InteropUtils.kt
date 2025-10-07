@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.internals

import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.posix.memcpy
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

fun NSData.toByteArray(): ByteArray {
    if(length>Int.MAX_VALUE.toULong()) throw IndexOutOfBoundsException("length is too large")
    return ByteArray(length.toInt()).apply {
        if (length > 0uL)
            usePinned {
                memcpy(it.addressOf(0), bytes, length)
            }
    }
}

@OptIn(BetaInteropApi::class)
fun ByteArray.toNSData(): NSData = memScoped {
    NSData.create(bytes = allocArrayOf(this@toNSData), length = this@toNSData.size.toULong())
}

fun NSError.toNiceString(): String {
    val sb = StringBuilder("[${if(domain != null) "$domain error, " else ""}code $code] $localizedDescription\n")
    localizedFailureReason?.let { sb.append("Because: $it") }
    localizedRecoverySuggestion?.let { sb.append("Try: $it") }
    localizedRecoveryOptions?.let { sb.append("Try also:\n - ${it.joinToString("\n - ")}\n") }
    return sb.toString()
}

class CoreFoundationException(val nsError: NSError): Throwable(nsError.toNiceString())
class corecall private constructor(val error: CPointer<CFErrorRefVar>, @PublishedApi internal val memScope: MemScope) {
    /** Produce a Core Foundation reference whose lifetime is equal to that of the corecall */
    inline fun <reified T: CFTypeRef?> giveToCF(v: Any?) =
        memScope.giveToCF<T>(v)
    /** Helper for calling Core Foundation functions, and bridging exceptions across.
     *
     * Usage:
     * ```
     * corecall { SomeCoreFoundationFunction(arg1, arg2, ..., error) }
     * ```
     * `error` is provided by the implicit receiver object, and will be mapped to a
     * `CoreFoundationException` if an error occurs.
     */
    companion object {
        @OptIn(BetaInteropApi::class)
        operator fun <T> invoke(call: corecall.()->T?) : T {
            memScoped {
                val errorH = alloc<CFErrorRefVar>()
                val result = corecall(errorH.ptr, this@memScoped).call()
                val error = errorH.value
                when {
                    (result != null) && (error == null) -> return result
                    (result == null) && (error != null) ->
                        throw CoreFoundationException(error.takeFromCF<NSError>())
                    else -> throw IllegalStateException("Invalid state returned by Core Foundation call")
                }
            }
        }
    }
}
class SwiftException(message: String): Throwable(message)
class swiftcall private constructor(val error: CPointer<ObjCObjectVar<NSError?>>) {
    /** Helper for calling swift-objc-mapped functions, and bridging exceptions across.
     *
     * Usage:
     * ```
     * swiftcall { SwiftObj.func(arg1, arg2, .., argN, error) }
     * ```
     * `error` is provided by the implicit receiver object, and will be mapped to a
     * `SwiftException` if the swift call throws.
     */
    companion object {
        @OptIn(BetaInteropApi::class)
        operator fun <T> invoke(call: swiftcall.()->T?): T {
            memScoped {
                val errorH = alloc<ObjCObjectVar<NSError?>>()
                val result = swiftcall(errorH.ptr).call()
                val error = errorH.value
                when {
                    (result != null) && (error == null) -> return result
                    (result == null) && (error != null) -> throw SwiftException(error.toNiceString())
                    else -> throw IllegalStateException("Invalid state returned by Swift")
                }
            }
        }
    }
}

@OptIn(ExperimentalNativeApi::class)
class OwnedCFValue<T: CFTypeRef> constructor(val value: T) {
    @Suppress("UNUSED")
    private val cleaner = createCleaner(value, ::CFRelease)
}

@Suppress("NOTHING_TO_INLINE") inline fun <T: CFTypeRef> T.manage() = OwnedCFValue(this)

/** Produce a Core Foundation reference whose lifetime is that of the containing [DeferScope] */
inline fun <reified T: CFTypeRef?> DeferScope.giveToCF(v: Any?) = when(v) {
    null -> v
    is Boolean -> if (v) kCFBooleanTrue else kCFBooleanFalse
    is CValuesRef<*> -> v
    else -> CFBridgingRetain(v).also { ref -> this@giveToCF.defer { CFRelease(ref) } }
} as T

inline fun <reified T> CFTypeRef?.takeFromCF() = CFBridgingRelease(this) as T

fun DeferScope.cfDictionaryOf(vararg pairs: Pair<*,*>): CFDictionaryRef {
    val dict = CFDictionaryCreateMutable(null, pairs.size.toLong(),
        kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)!!
    defer { CFRelease(dict) } // free it after the memscope finishes
    pairs.forEach { (k,v) -> dict[k] = v }
    return dict
}

class CFDictionaryInitScope private constructor() {
    private val pairs = mutableListOf<Pair<*,*>>()

    fun map(pair: Pair<*,*>) { pairs.add(pair) }
    infix fun Any?.mapsTo(other: Any?) { map(this to other) }

    companion object {
        fun resolve(scope: DeferScope, fn: CFDictionaryInitScope.()->Unit) =
            scope.cfDictionaryOf(*CFDictionaryInitScope().apply(fn).pairs.toTypedArray())
    }
}
fun DeferScope.createCFDictionary(pairs: CFDictionaryInitScope.()->Unit) =
    CFDictionaryInitScope.resolve(this, pairs)

inline operator fun <reified T> CFDictionaryRef.get(key: Any?): T = memScoped {
    CFDictionaryGetValue(this@get, giveToCF(key)).takeFromCF<T>()
}

@Suppress("NOTHING_TO_INLINE")
inline operator fun CFMutableDictionaryRef.set(key: Any?, value: Any?) = memScoped {
    CFDictionarySetValue(this@set, giveToCF(key), giveToCF(value))
}
