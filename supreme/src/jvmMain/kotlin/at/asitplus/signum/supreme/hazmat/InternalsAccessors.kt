package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.supreme.sign.SupremeEphemeralJvmSigner
import at.asitplus.signum.supreme.sign.Signer
import java.security.PrivateKey

/** The underlying JCA [PrivateKey] object. */
@HazardousMaterials
val Signer.jcaPrivateKey get() = (this as? SupremeEphemeralJvmSigner)?.privateKey
