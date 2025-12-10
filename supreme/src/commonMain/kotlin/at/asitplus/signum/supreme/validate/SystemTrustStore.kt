package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi

/**
 * System Trust store containing Trust Anchors shipped by default. Provided on a best-effort basis. May be incomplete.
 */
@ExperimentalPkiApi
expect val SystemTrustStore: Set<TrustAnchor>