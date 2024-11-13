package at.asitplus.signum.supreme.hazmat

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.supreme.sign.EphemeralKey
import at.asitplus.signum.supreme.sign.EphemeralKeyBase
import at.asitplus.signum.supreme.sign.EphemeralSigner
import at.asitplus.signum.supreme.sign.Signer
import java.security.PrivateKey

/** The underlying JCA [PrivateKey] object. */
@HazardousMaterials
val EphemeralKey.jcaPrivateKey get() = (this as? EphemeralKeyBase<*>)?.privateKey as? PrivateKey

/** The underlying JCA [PrivateKey] object. */
@HazardousMaterials
val Signer.jcaPrivateKey get() = (this as? EphemeralSigner)?.privateKey
