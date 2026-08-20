package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.supreme.os.AndroidKeystoreSigner
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.SupremeEphemeralJvmSigner
import java.security.PrivateKey

/** The underlying JCA [PrivateKey] object. */
@HazardousMaterials
val Signer.jcaPrivateKey get() = when (this) {
    is SupremeEphemeralJvmSigner -> this.privateKey
    is AndroidKeystoreSigner -> this.jcaPrivateKey
    else -> null
}
