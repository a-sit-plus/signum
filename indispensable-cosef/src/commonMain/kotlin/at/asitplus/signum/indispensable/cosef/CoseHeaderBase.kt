package at.asitplus.signum.indispensable.cosef

/**
 * Common header parameters of (https://www.rfc-editor.org/rfc/rfc9052.html#section-3.1), plus
 * `x5chain` [RFC 9360](https://www.rfc-editor.org/rfc/rfc9360.html) and `typ`
 * [RFC 9596](https://www.rfc-editor.org/rfc/rfc9596.html), for application-defined COSE header models.
 *
 * Applications needing further parameters implement this
 * interface in their own `@Serializable` class and decode headers with it, see [CoseHeaderWrapped].
 */
interface CoseHeaderBase {
    /** `alg` (label 1) */
    val algorithm: CoseAlgorithm?
    /** `content type` (label 3) */
    val contentType: String?
    /** `kid` (label 4) */
    val kid: ByteArray?
    /** `IV` (label 5) */
    val iv: ByteArray?
    /** `Partial IV` (label 6) */
    val partialIv: ByteArray?
    /** `x5chain` (label 33), end-entity certificate first */
    val certificateChain: List<ByteArray>?
    /** `typ` (label 16) */
    val type: String?
}