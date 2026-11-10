package at.asitplus.signum.indispensable.cosef

import kotlinx.serialization.KSerializer
import kotlin.time.Instant

@Deprecated("Moved", replaceWith = ReplaceWith("at.asitplus.signum.indispensable.io.InstantLongSerializer" ))
object InstantLongSerializer : KSerializer<Instant> by at.asitplus.signum.indispensable.io.InstantLongSerializer
