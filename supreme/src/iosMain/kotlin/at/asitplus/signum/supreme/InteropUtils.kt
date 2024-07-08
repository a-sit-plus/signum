@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme

import kotlinx.cinterop.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
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
    val sb = StringBuilder("[Code $code] $localizedDescription\n")
    localizedFailureReason?.let { sb.append("Because: $it") }
    localizedRecoverySuggestion?.let { sb.append("Try: $it") }
    localizedRecoveryOptions?.let { sb.append("Try also:\n - ${it.joinToString("\n - ")}\n") }
    return sb.toString()
}

class CFCryptoOperationFailed(thing: String, osStatus: OSStatus) : CryptoOperationFailed(buildMessage(thing, osStatus)) {
    companion object {
        private fun buildMessage(thing: String, osStatus: OSStatus): String {
            val errorMessage = SecCopyErrorMessageString(osStatus, null).takeFromCF<String?>()
            return "Failed to $thing: [code $osStatus] ${errorMessage ?: "unspecified security error"}"
        }
    }
}

class CoreFoundationException(message: String): Throwable(message)
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
                        throw CoreFoundationException(error.takeFromCF<NSError>().toNiceString())
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

internal class swiftasync<T> private constructor(val callback: (T?, NSError?)->Unit) {
    /** Helper for calling swift-objc-mapped async functions, and bridging exceptions across.
     *
     * Usage:
     * ```
     * swiftasync { SwiftObj.func(arg1, arg2, .., argN, callback) }
     * ```
     * `error` is provided by the implicit receiver object, and will be mapped to a
     * `SwiftException` if the swift call throws.
     */
    companion object {
        suspend operator fun <T> invoke(call: swiftasync<T>.()->Unit): T {
            var result: T? = null
            var error: NSError? = null
            val mut = Mutex(true)
            swiftasync<T> { res, err -> result = res; error = err; mut.unlock() }.call()
            mut.withLock {
                val res = result
                val err = error
                when {
                    (res != null) && (err == null) -> return res
                    (res == null) && (err != null) -> throw SwiftException(err.toNiceString())
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
