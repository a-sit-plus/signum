package at.asitplus.crypto.datatypes

/**
 * Currently, we only support SHA-256
 */
enum class Digest {

    //TODO expand, maybe even add the okio dependency and plug it in here?
    // at least mention that okio providres it?
    // the jws module laredy has a hard dependenc yon okio, so…
    SHA256;

}