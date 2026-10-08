package at.asitplus.signum.indispensable

interface Encodable {
    /** Open key identifying the format of a decoded source. */
    interface Representation

    /**
     * Records only the source representation from which this value was decoded, if any:
     * the format key paired with the original decoded model.
     *
     * Null when no source representation is retained, including for programmatically constructed
     * values. Encoding or accessing a representation never populates or replaces this property.
     */
    val sourceRepresentation: Pair<Representation, Any>? get() = null
}

/** Returns the original model only when it belongs to [format]. Never caches generated models. */
fun Encodable.sourceRepresentationFor(format: Encodable.Representation): Any? =
    sourceRepresentation?.takeIf { it.first == format }?.second

/** A typed decoding target, normally a companion object. */
interface Decodable<out T : Encodable>
