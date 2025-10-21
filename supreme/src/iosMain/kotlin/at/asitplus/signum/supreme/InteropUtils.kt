@file:OptIn(ExperimentalForeignApi::class)

package at.asitplus.signum.supreme

import at.asitplus.signum.CryptoOperationFailed
import at.asitplus.signum.internals.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.cinterop.*
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRef
import platform.Foundation.NSError
import platform.Security.SecCopyErrorMessageString
import platform.darwin.OSStatus
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

@OptIn(ExperimentalNativeApi::class)
class AutofreeVariable<T: CFTypeRef> internal constructor(
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
    private val cleaner = createCleaner(Pair(arena, variable)) {
        it.second.value?.let(::CFRelease)
        it.first.clear()
    }
    internal val ptr get() = variable.ptr
    internal val value get() = variable.value
}

class CFCryptoOperationFailed(thing: String, val osStatus: OSStatus) : CryptoOperationFailed(buildMessage(thing, osStatus)) {
    companion object {
        private fun buildMessage(thing: String, osStatus: OSStatus): String {
            val errorMessage = SecCopyErrorMessageString(osStatus, null).takeFromCF<String?>()
            return "Failed to $thing: [code $osStatus] ${errorMessage ?: "unspecified security error"}"
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