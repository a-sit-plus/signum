package at.asitplus.signum.indispensable.sign

import at.asitplus.signum.indispensable.CryptoSignature
import kotlin.jvm.JvmInline

open class UserInitiatedCancellation(message: String?, cause: Throwable?): Throwable(message, cause)
class UnlockFailed(message: String? = null, cause: Throwable? = null) : UserInitiatedCancellation(message, cause)

sealed interface SignatureResult<out T: CryptoSignature> {
    /** The signature succeeded. A signature is contained. */
    @JvmInline value class Success<T: CryptoSignature>(val signature: T): SignatureResult<T>
    /** The signature failed for expected reasons. Typically, this is because the user cancelled the operation. */
    @JvmInline value class Failure(val problem: UserInitiatedCancellation): SignatureResult<Nothing>

    companion object {
        inline fun <SigT: CryptoSignature> make(fn: ()->SigT): SignatureResult<SigT> =
            try {Success(fn()) }
            catch (x: UserInitiatedCancellation) { Failure(x) }
    }
}
/** Retrieves the contained signature, asserting it exists. If it does not exist, throws the contained problem. */
val <T: CryptoSignature> SignatureResult<T>.signature: T get() = when (this) {
    is SignatureResult.Success -> this.signature
    is SignatureResult.Failure -> throw this.problem
}

/** Modifies the contained [CryptoSignature], usually in order to reinterpret it as a more narrow type. */
inline fun <T: CryptoSignature, S: CryptoSignature> SignatureResult<T>.map(block: (T)->S) =
    when (this) {
        is SignatureResult.Success -> SignatureResult.Success(block(this.signature))
        is SignatureResult.Failure -> this
    }
