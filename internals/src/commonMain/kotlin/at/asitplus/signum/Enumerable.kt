package at.asitplus.signum

/**
 * Marker interface for types that can be enumerated.
 * Every type implementing [Enumerable] is expected
 * to provide a companion object that implements [Enumeration] containing all possible instances of the type.
 */
interface Enumerable

/**
 * Provides a collection of all possible instances of a given [Enumerable] type.
 * Implemented by the companion object of a type implementing [Enumerable]
 */
interface Enumeration<T: Enumerable> {

    /**
     * The order of elements in [entries] is not guaranteed.
     * */
    val entries: Iterable<T>
}