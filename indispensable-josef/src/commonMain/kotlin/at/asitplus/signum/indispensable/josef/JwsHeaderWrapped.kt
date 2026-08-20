package at.asitplus.signum.indispensable.josef

/**
 * An effective [JwsHeader] together with the names of the members carried in its unprotected fragment.
 *
 * Member placement belongs to a concrete JSON JWS representation rather than to [JwsHeader] itself.
 */
data class JwsHeaderWrapped(
    val header: JwsHeader,
    val unprotectedMembers: List<String> = emptyList(),
)
