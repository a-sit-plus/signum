@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.supreme.AutofreeVariable
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.supreme.os.IosSigner
import at.asitplus.signum.supreme.os.IosSignerSigningConfiguration
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.EphemeralKeyBase
import at.asitplus.signum.supreme.sign.EphemeralSigner
import at.asitplus.signum.supreme.sign.Signer
import kotlinx.cinterop.ExperimentalForeignApi
import platform.Security.SecKeyRef

/** The underlying SecKeyRef referencing the ephemeral key's private key. */
@HazardousMaterials
@Suppress("UNCHECKED_CAST")
val EphemeralKey.secKeyRef get() = (this as? EphemeralKeyBase<*>)?.privateKey as? AutofreeVariable<SecKeyRef>

/** The underlying SecKeyRef referencing the signer's private key.
 * **⚠️ If returned from a keychain signer, must be used immediately. Do not store long term. ⚠️** */
@HazardousMaterials
val Signer.secKeyRef get() = when (this) {
    is EphemeralSigner -> this.privateKey
    is IosSigner -> this.privateKeyManager.get(IosSignerSigningConfiguration())
    else -> null
}
