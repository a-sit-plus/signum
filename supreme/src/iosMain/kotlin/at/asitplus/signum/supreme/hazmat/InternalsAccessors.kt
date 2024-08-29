@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.os.UnlockedIosSigner
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.EphemeralKeyBase
import at.asitplus.signum.supreme.sign.EphemeralKeyRef
import at.asitplus.signum.supreme.sign.EphemeralSigner
import at.asitplus.signum.supreme.sign.Signer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.value

/** The underlying SecKeyRef referencing the ephemeral key's private key.
 *
 * **⚠️ Must not be used beyond the EphemeralKey's lifetime. ⚠️** */
@HazardousMaterials
val EphemeralKey.secKeyRef get() = ((this as? EphemeralKeyBase<*>)?.privateKey as? EphemeralKeyRef)?.key?.value

/** The underlying SecKeyRef referencing the signer's private key. Only available on ephemeral signers or unlocked signers.
 * Not available on locked signers. (The ref isn't retrieved from the keychain until unlock time.)
 *
 * **⚠️ Must not be used beyond the signer's lifetime/scope. ⚠️** */
@HazardousMaterials
val Signer.secKeyRef get() = when (this) {
    is EphemeralSigner -> this.privateKey.key.value
    is UnlockedIosSigner -> this.privateKeyRef
    else -> null
}
