package at.asitplus.signum.indispensable.josef

/**
 * Type-safe (one-way) view of an effective [JwsHeader] together with the names of the members in its unprotected fragment.
 *
 * Header fragments are owned by the concrete [JWS] representation.
 */
@ConsistentCopyVisibility
data class JwsHeaderWrapped internal constructor(
    val header: JwsHeader,
    val unprotectedMembers: Set<String>,
)
