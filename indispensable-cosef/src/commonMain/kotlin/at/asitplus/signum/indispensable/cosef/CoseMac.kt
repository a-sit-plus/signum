package at.asitplus.signum.indispensable.cosef

data class CoseMac<P : Any?> internal constructor(
    val protectedHeader: CoseHeader,
    val unprotectedHeader: CoseHeader? = null,
    val payload: P?,
    val tag: ByteArray,
    val wireFormat: CoseBytes,
) {
}