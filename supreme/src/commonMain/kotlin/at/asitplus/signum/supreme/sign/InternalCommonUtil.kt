package at.asitplus.signum.supreme.sign

import at.asitplus.signum.supreme.UnsupportedCryptoException

/**
 * Resolve [what] differently based on whether the [v]alue was [spec]ified.
 *
 * * [spec] = `true`: Check if [valid] contains [nameMap] applied to [v], return [v] if yes, throw otherwise
 * * [spec] = `false`: Check if [valid] contains exactly one element, if yes, return the [E] from [possible] for which [nameMap] returns that element, throw otherwise
 */
internal inline fun <reified E> resolveOption(what: String, valid: Array<String>, possible: Sequence<E>, spec: Boolean, v: E, crossinline nameMap: (E)->String): E =
    when (spec) {
        true -> {
            val vStr = nameMap(v)
            if (!valid.any { it.equals(vStr, ignoreCase=true) })
                throw IllegalArgumentException("Key does not support $what $v; supported: ${valid.joinToString(", ")}")
            v
        }
        false -> {
            if (valid.size != 1)
                throw IllegalArgumentException("Key supports multiple ${what}s (${valid.joinToString(", ")}). You need to specify $what in signer configuration.")
            val only = valid.first()
            possible.find {
                nameMap(it).equals(only, ignoreCase=true)
            } ?: throw UnsupportedCryptoException("Unsupported $what $only")
        }
    }
internal inline fun <reified E> resolveOption(what: String, valid: Set<E>, possible: Sequence<E>, spec: Boolean, v: E, crossinline nameMap: (E)->String): E =
    resolveOption(what, valid.map(nameMap).toTypedArray(), possible, spec, v, nameMap)
