package at.asitplus.signum.indispensable.cosef

import kotlinx.serialization.Serializable

/**
 * Common COSE parameters. Applications own their concrete @Serializable header models and annotations.
 * Defaults describe absent parameters; serializer descriptors alone do not establish their presence.
 * Protected and unprotected buckets are always separate models.
 */
interface CoseHeader {
    val algorithm: CoseAlgorithm? get() = null
    val criticalHeaders: List<CoseHeaderLabel>? get() = null
    val contentType: CoseContentType? get() = null
    val kid: ByteArray? get() = null
    val iv: ByteArray? get() = null
    val partialIv: ByteArray? get() = null
    val certificateChain: List<ByteArray>? get() = null
    val type: String? get() = null
    val certificateHash: CoseCertificateHash? get() = null
    val certificateUrl: String? get() = null
    val cwtClaims: CwtClaims? get() = null
}

/** Encodes an empty bucket as a CBOR map. Protected empty maps are emitted as h'' on creation. */
@Serializable
data object EmptyCoseHeader : CoseHeader
