package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import kotlin.jvm.JvmInline

/** These map to SignatureResult.Failure instead of SignatureResult.Error */
sealed class UserInitiatedCancellationReason(message: String?, cause: Throwable?): Throwable(message, cause)
class UnlockFailed(message: String? = null, cause: Throwable? = null) : UserInitiatedCancellationReason(message, cause)

sealed interface SignatureResult<out T: CryptoSignature.RawByteEncodable> {
    /** The signature succeeded. A signature is contained. */
    @JvmInline value class Success<T: CryptoSignature.RawByteEncodable>(val signature: T): SignatureResult<T>
    /** The signature failed for expected reasons. Typically, this is because the user cancelled the operation. */
    @JvmInline value class Failure(val problem: UserInitiatedCancellationReason): SignatureResult<Nothing>
    /** The signature failed for an unexpected reason. The thrown exception is contained. */
    @JvmInline value class Error(val exception: Throwable): SignatureResult<Nothing>
    companion object {
        /** Constructs a suitable failed SignatureResult from the exception.
         * [UserInitiatedCancellationReason] and subclasses map to [Failure], anything else maps to [Error]. */
        fun FromException(x: Throwable): SignatureResult<Nothing> = when (x) {
            is UserInitiatedCancellationReason -> SignatureResult.Failure(x)
            else -> SignatureResult.Error(x)
        }
    }
}
val SignatureResult<*>.isSuccess get() = (this is SignatureResult.Success)
/** Retrieves the contained signature, asserting it exists. If it does not exist, throws the contained problem. */
val <T: CryptoSignature.RawByteEncodable> SignatureResult<T>.signature: T get() = when (this) {
    is SignatureResult.Success -> this.signature
    is SignatureResult.Failure -> throw this.problem
    is SignatureResult.Error -> throw this.exception
}
/** Retrieves the contained signature, if one exists. */
val <T: CryptoSignature.RawByteEncodable> SignatureResult<T>.signatureOrNull: T? get() = when (this) {
    is SignatureResult.Success -> this.signature
    else -> null
}
/** Transforms this SignatureResult into a [KmmResult]. Both [Failure] and [Error] map to [KmmResult.Failure]. */
fun <T: CryptoSignature.RawByteEncodable> SignatureResult<T>.asKmmResult(): KmmResult<T> = catching { this.signature }

/** Modifies the contained [CryptoSignature], usually in order to reinterpret it as a more narrow type. */
inline fun <T: CryptoSignature.RawByteEncodable, S: CryptoSignature.RawByteEncodable> SignatureResult<T>.map(block: (T)->S) =
    when (this) {
        is SignatureResult.Success -> SignatureResult.Success(block(this.signature))
        is SignatureResult.Failure -> this
        is SignatureResult.Error -> this
    }

/** Modifies the contained [CryptoSignature], usually in order to reinterpret it as a more narrow type. */
inline fun <T: CryptoSignature.RawByteEncodable, S: CryptoSignature.RawByteEncodable> SignatureResult<T>
        .modify(block: KmmResult<T>.()->KmmResult<S>) =
    catching { this.signature }.block().fold(
        onSuccess = { SignatureResult.Success(it) },
        onFailure = { SignatureResult.FromException(it) })

/** Runs the block, catches exceptions, and maps to [SignatureResult].
 * @see SignatureResult.FromException */
internal inline fun signCatching(fn: ()->CryptoSignature.RawByteEncodable): SignatureResult<*> =
    catching { fn() }.fold(
        onSuccess = { SignatureResult.Success(it) },
        onFailure = { SignatureResult.FromException(it) })
