package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.os.LockedAndroidKeystoreSigner
import at.asitplus.signum.supreme.os.UnlockedAndroidKeystoreSigner
import at.asitplus.signum.supreme.sign.AndroidEphemeralSigner
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.EphemeralKeyBase
import at.asitplus.signum.supreme.sign.Signer
import java.security.PrivateKey

/** The underlying JCA [PrivateKey] object. */
@HazardousMaterials
val EphemeralKey.jcaPrivateKey get() = (this as? EphemeralKeyBase<*>)?.privateKey as? PrivateKey

/** The underlying JCA [PrivateKey] object. Not available for unlocked KeyStore signers; see [jcaSignatureInstance]. */
@HazardousMaterials
val Signer.jcaPrivateKey get() = when (this) {
    is AndroidEphemeralSigner -> this.privateKey
    is LockedAndroidKeystoreSigner -> this.jcaPrivateKey
    else -> null
}

/** The underlying, unlocked JCA [Signature] object. */
@HazardousMaterials
val UnlockedAndroidKeystoreSigner.jcaSignatureInstance get() = this.jcaSig
