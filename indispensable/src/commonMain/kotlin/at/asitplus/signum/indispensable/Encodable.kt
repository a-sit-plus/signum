package at.asitplus.signum.indispensable

interface Encodable {
    /** Open key for an original representation retained by a format or codec. */
    interface Representation
    val representations: Map<Representation, Any>
}

/** A typed decoding target, normally a companion object. */
interface Decodable<out T : Encodable>
