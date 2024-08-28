package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.os.LockedAndroidKeystoreSigner
import at.asitplus.signum.supreme.sign.AndroidEphemeralSigner
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.EphemeralKeyBase
import at.asitplus.signum.supreme.sign.Signer
import java.security.PrivateKey

@HazardousMaterials
val EphemeralKey.jcaPrivateKey get() = (this as? EphemeralKeyBase<*>)?.privateKey as? PrivateKey
@HazardousMaterials
val Signer.jcaPrivateKey get() = when (this) {
    is AndroidEphemeralSigner -> this.privateKey
    is LockedAndroidKeystoreSigner -> this.jcaPrivateKey
    else -> null
}
