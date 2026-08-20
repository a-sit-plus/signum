@file:OptIn(ExperimentalForeignApi::class)
package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.supreme.os.IosSigner
import at.asitplus.signum.supreme.os.IosSignerSigningConfiguration
import at.asitplus.signum.supreme.sign.SupremeIosEphemeralSigner
import at.asitplus.signum.supreme.sign.Signer
import kotlinx.cinterop.ExperimentalForeignApi

/** The underlying SecKeyRef referencing the signer's private key.
 * **⚠️ If returned from a keychain signer, must be used immediately. Do not store long term. ⚠️** */
@HazardousMaterials
val Signer.secKeyRef get() = when (this) {
    is SupremeIosEphemeralSigner -> this.privateKey
    is IosSigner -> this.privateKeyManager.get(IosSignerSigningConfiguration())
    else -> null
}
