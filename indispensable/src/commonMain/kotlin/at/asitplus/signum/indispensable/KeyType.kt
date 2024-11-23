package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.KeyType.*

sealed interface KeyType {
    object RSA : KeyType
    object EC : KeyType
    object NONE : KeyType //TODO: this is a band-aid to deal with MAC
}

val KeyType.entries: List<KeyType>
    get() = listOf(RSA, EC, NONE)
