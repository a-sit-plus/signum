package at.asitplus.signum.supreme

import at.asitplus.signum.indispensable.CryptoSignature
import kotlin.jvm.JvmInline

sealed class UserInitiatedCancellation(message: String?, cause: Throwable?): Throwable(message, cause)
class UnlockFailed(message: String? = null, cause: Throwable? = null) : UserInitiatedCancellation(message, cause)

sealed interface SignatureResult<out T: CryptoSignature.RawByteEncodable> {
    /** The signature succeeded. A signature is contained. */
    @JvmInline value class Success<T: CryptoSignature.RawByteEncodable>(val signature: T): SignatureResult<T>
    /** The signature failed for expected reasons. Typically, this is because the user cancelled the operation. */
    @JvmInline value class Failure(val problem: UserInitiatedCancellation): SignatureResult<Nothing>
}
/** Retrieves the contained signature, asserting it exists. If it does not exist, throws the contained problem. */
val <T: CryptoSignature.RawByteEncodable> SignatureResult<T>.signature: T get() = when (this) {
    is SignatureResult.Success -> this.signature
    is SignatureResult.Failure -> throw this.problem
}

/** Modifies the contained [CryptoSignature], usually in order to reinterpret it as a more narrow type. */
inline fun <T: CryptoSignature.RawByteEncodable, S: CryptoSignature.RawByteEncodable> SignatureResult<T>.map(block: (T)->S) =
    when (this) {
        is SignatureResult.Success -> SignatureResult.Success(block(this.signature))
        is SignatureResult.Failure -> this
    }

internal inline fun signCatching(fn: ()->CryptoSignature.RawByteEncodable): SignatureResult<*> =
    try {
        SignatureResult.Success(fn())
    } catch (x: UserInitiatedCancellation) {
        SignatureResult.Failure(x)
    }
