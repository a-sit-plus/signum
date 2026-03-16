package at.asitplus.signum.indispensable

import at.asitplus.awesn1.crypto.DerDefaults
import kotlinx.serialization.ExperimentalSerializationApi

private var signumDefaultDerRegistered = false

/**
 * Registers Signum's default-DER serialization hooks.
 *
 * This must run before the first access to awesn1's default `DER` instance if callers want generic
 * `Signature` / `SignatureValue` deserialization to work without specifying a concrete subtype.
 */
@OptIn(ExperimentalSerializationApi::class)
fun registerSignumDefaultDerSerializers() {
    if (signumDefaultDerRegistered) return
    DerDefaults.registerDerSerializers()
    signumDefaultDerRegistered = true
}
