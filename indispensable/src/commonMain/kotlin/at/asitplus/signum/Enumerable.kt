package at.asitplus.signum

interface Enumerable

interface Enumeration<T : Enumerable> {
    val entries: Iterable<T>
}
