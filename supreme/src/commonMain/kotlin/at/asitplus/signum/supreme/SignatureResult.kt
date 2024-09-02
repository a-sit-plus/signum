package at.asitplus.signum.supreme

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoSignature
import kotlin.jvm.JvmInline

/** These map to SignatureResult.Failure instead of SignatureResult.Error */
sealed class UserInitiatedCancellationReason(message: String?, cause: Throwable?): Throwable(message, cause)
class UnlockFailed(message: String? = null, cause: Throwable? = null) : UserInitiatedCancellationReason(message, cause)

sealed interface SignatureResult {
    @JvmInline
    value class Success(val signature: CryptoSignature): SignatureResult
    @JvmInline
    value class Failure(val problem: UserInitiatedCancellationReason): SignatureResult
    @JvmInline
    value class Error(val exception: Throwable): SignatureResult
}
val SignatureResult.isSuccess get() = (this is SignatureResult.Success)
/** Retrieves the contained signature, asserting it exists. If it does not exist, throws the contained problem. */
val SignatureResult.signature: CryptoSignature get() = when (this) {
    is SignatureResult.Success -> this.signature
    is SignatureResult.Failure -> throw this.problem
    is SignatureResult.Error -> throw this.exception
}
/** Retrieves the contained signature, if one exists. */
val SignatureResult.signatureOrNull: CryptoSignature? get() = when (this) {
    is SignatureResult.Success -> this.signature
    else -> null
}
/** Transforms this SignatureResult into a [KmmResult]. Both [Failure] and [Error] map to [KmmResult.Failure]. */
fun SignatureResult.wrap(): KmmResult<CryptoSignature> = catching { this.signature }

internal inline fun signCatching(fn: ()->CryptoSignature): SignatureResult =
    runCatching { fn() }.fold(
        onSuccess = SignatureResult::Success,
        onFailure = {
            if (it is UserInitiatedCancellationReason) SignatureResult.Failure(it)
            else SignatureResult.Error(it)
        })
