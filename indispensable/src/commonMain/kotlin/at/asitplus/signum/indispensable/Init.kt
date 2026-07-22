package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.DigestProvider
import at.asitplus.signum.indispensable.digest.IndispensableDigestsProvider
import at.asitplus.signum.ServiceLoader

/** NEVER CALL THIS DIRECTLY -> use [Indispensable.init] */
internal expect fun indispensablePlatformInit()
object Indispensable {
    private val initialize by lazy {
        ServiceLoader.register<DigestProvider>(IndispensableDigestsProvider)
        indispensablePlatformInit()
    }
    // this should be replaced by sweetspi
    fun init() {
        initialize
    }
}
