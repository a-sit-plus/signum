@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.indispensable

import kotlinx.cinterop.*
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionaryGetValue
import platform.CoreFoundation.CFDictionaryRef
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFMutableDictionaryRef
import platform.CoreFoundation.CFTypeRef
import platform.CoreFoundation.kCFBooleanFalse
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Foundation.CFBridgingRelease
import platform.Foundation.CFBridgingRetain
import platform.Foundation.NSData
import platform.Foundation.NSError
import platform.Foundation.create
import platform.Security.SecCopyErrorMessageString
import platform.darwin.OSStatus
import platform.posix.memcpy
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

//TODO: this is duplicated code from Supreme. Come up with a better strategy without polluting the public API
@OptIn(ExperimentalNativeApi::class)
class AutofreeVariable<T: CPointer<*>> internal constructor(
    arena: Arena,
    private val variable: CPointerVarOf<T>) {
    companion object {
        internal inline operator fun <reified T: CPointer<*>> invoke(): AutofreeVariable<T> {
            val arena = Arena()
            val variable = arena.alloc<CPointerVarOf<T>>()
            return AutofreeVariable<T>(arena, variable)
        }
    }
    @Suppress("UNUSED")
    private val cleaner = createCleaner(arena, Arena::clear)
    internal val ptr get() = variable.ptr
    internal val value get() = variable.value
}

internal fun NSData.toByteArray(): ByteArray = ByteArray(length.toInt()).apply {
    usePinned {
        memcpy(it.addressOf(0), bytes, length)
    }
}

@OptIn(BetaInteropApi::class)
internal fun ByteArray.toNSData(): NSData = memScoped {
    NSData.create(bytes = allocArrayOf(this@toNSData), length = this@toNSData.size.toULong())
}

private fun NSError.toNiceString(): String {
    val sb = StringBuilder("[${if(domain != null) "$domain error, " else ""}code $code] $localizedDescription\n")
    localizedFailureReason?.let { sb.append("Because: $it") }
    localizedRecoverySuggestion?.let { sb.append("Try: $it") }
    localizedRecoveryOptions?.let { sb.append("Try also:\n - ${it.joinToString("\n - ")}\n") }
    return sb.toString()
}



class CoreFoundationException(val nsError: NSError): Throwable(nsError.toNiceString())
internal class corecall private constructor(val error: CPointer<CFErrorRefVar>) {
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
                val result = corecall(errorH.ptr).call()
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
internal class swiftcall private constructor(val error: CPointer<ObjCObjectVar<NSError?>>) {
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



internal inline fun <reified T: CFTypeRef?> Any?.giveToCF() = when(this) {
    null -> this
    is Boolean -> if (this) kCFBooleanTrue else kCFBooleanFalse
    is CValuesRef<*> -> this
    else -> CFBridgingRetain(this)
} as T
internal inline fun <reified T> CFTypeRef?.takeFromCF() = CFBridgingRelease(this) as T
internal fun MemScope.cfDictionaryOf(vararg pairs: Pair<*,*>): CFDictionaryRef {
    val dict = CFDictionaryCreateMutable(null, pairs.size.toLong(),
        kCFTypeDictionaryKeyCallBacks.ptr, kCFTypeDictionaryValueCallBacks.ptr)!!
    defer { CFBridgingRelease(dict) } // free it after the memscope finishes
    pairs.forEach { (k,v) -> dict[k] = v }
    return dict
}

internal class CFDictionaryInitScope private constructor() {
    private val pairs = mutableListOf<Pair<*,*>>()

    fun map(pair: Pair<*,*>) { pairs.add(pair) }
    infix fun Any?.mapsTo(other: Any?) { map(this to other) }

    internal companion object {
        fun resolve(scope: MemScope, fn: CFDictionaryInitScope.()->Unit) =
            scope.cfDictionaryOf(*CFDictionaryInitScope().apply(fn).pairs.toTypedArray())
    }
}
internal fun MemScope.createCFDictionary(pairs: CFDictionaryInitScope.()->Unit) =
    CFDictionaryInitScope.resolve(this, pairs)
internal inline operator fun <reified T> CFDictionaryRef.get(key: Any?): T =
    CFDictionaryGetValue(this, key.giveToCF()).takeFromCF<T>()

internal inline operator fun CFMutableDictionaryRef.set(key: Any?, value: Any?) =
    CFDictionarySetValue(this, key.giveToCF(), value.giveToCF())
