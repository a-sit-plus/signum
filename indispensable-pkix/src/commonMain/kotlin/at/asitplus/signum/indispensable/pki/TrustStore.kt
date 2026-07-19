package at.asitplus.signum.indispensable.pki

/** A source of [TrustAnchor]s used to seed certificate-path validation. */
interface TrustStore {
    val anchors: Set<TrustAnchor>
}

/** Wraps a fixed set of [anchors] as a [TrustStore]. */
fun TrustStore(anchors: Set<TrustAnchor>): TrustStore = object : TrustStore {
    override val anchors: Set<TrustAnchor> = anchors
}
