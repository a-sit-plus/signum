package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.digest.DigestProvider
import at.asitplus.signum.indispensable.digest.IndispensableDigestsProvider
import at.asitplus.signum.internals.ServiceLoader

object Indispensable {
    private val initialize by lazy {
        ServiceLoader.register<DigestProvider>(IndispensableDigestsProvider)
    }
    // this should be replaced by sweetspi
    fun init() {
        initialize
    }
}
