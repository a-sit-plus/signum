package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.BundledTrustStore

import at.asitplus.signum.indispensable.pki.TrustStore

// iOS exposes no user-queryable system trust store API, so the system store IS the build-time
// embedded bundle (the same Apple roots that feed [BundledTrustStore]).
actual val systemTrustStore: TrustStore? = BundledTrustStore
