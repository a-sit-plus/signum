package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.os.unlockedIosSigner
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.EphemeralKeyBase
import at.asitplus.signum.supreme.sign.EphemeralKeyRef
import at.asitplus.signum.supreme.sign.EphemeralSigner
import at.asitplus.signum.supreme.sign.Signer

@HazardousMaterials
val EphemeralKey.secKeyRef get() = ((this as? EphemeralKeyBase<*>)?.privateKey as? EphemeralKeyRef)?.key?.value
@HazardousMaterials
val Signer.secKeyRef get() = when (this) {
    is EphemeralSigner -> this.privateKey.key.value
    is unlockedIosSigner -> this.privateKeyRef
    else -> null
}
