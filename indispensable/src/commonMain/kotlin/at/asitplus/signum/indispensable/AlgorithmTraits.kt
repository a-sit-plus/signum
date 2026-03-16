package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.asymmetric.RsaEncryptionPadding
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.symmetric.AesGcmAlgorithm
import at.asitplus.signum.indispensable.symmetric.ChaCha20Poly1305Algorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm

interface WithDigest {
    val digest: Digest?
}

interface WithCurveConstraint {
    val requiredCurve: ECCurve?
}

interface WithRsaSignaturePadding {
    val padding: RsaSignaturePadding
}

interface WithRsaEncryptionPadding {
    val padding: RsaEncryptionPadding
}

interface WithKeySize {
    val keySize: BitLength
}

interface WithOutputLength {
    val outputLength: BitLength
}

interface SignatureMappingFamily {
    val id: String
}

data object EcdsaSignatureMappingFamily : SignatureMappingFamily {
    override val id: String = "ecdsa"
}

data object RsaSignatureMappingFamily : SignatureMappingFamily {
    override val id: String = "rsa"
}

data class SignatureMappingKey(
    val family: SignatureMappingFamily,
    val digest: Digest?,
    val curve: ECCurve?,
    val rsaSignaturePadding: RsaSignaturePadding?,
)

data class MacMappingKey(
    val digest: Digest?,
    val outputLength: BitLength,
)

interface SymmetricMappingKind {
    val id: String
}

data object AesGcmSymmetricMappingKind : SymmetricMappingKind {
    override val id: String = "aes-gcm"
}

data object ChaCha20Poly1305SymmetricMappingKind : SymmetricMappingKind {
    override val id: String = "chacha20-poly1305"
}

data class SymmetricMappingKey(
    val kind: SymmetricMappingKind,
    val keySize: BitLength,
)

data class AsymmetricEncryptionMappingKey(
    val rsaEncryptionPadding: RsaEncryptionPadding?,
)

data class X509SignatureKey(
    val oid: ObjectIdentifier,
    val parameters: List<Asn1Element>,
)

fun SignatureAlgorithm.signatureMappingKeyOrNull(): SignatureMappingKey? = when {
    this is WithCurveConstraint && this is WithDigest -> SignatureMappingKey(
        family = EcdsaSignatureMappingFamily,
        digest = digest,
        curve = requiredCurve,
        rsaSignaturePadding = null,
    )

    this is WithRsaSignaturePadding && this is WithDigest -> SignatureMappingKey(
        family = RsaSignatureMappingFamily,
        digest = digest,
        curve = null,
        rsaSignaturePadding = padding,
    )

    else -> null
}

fun MessageAuthenticationCode.macMappingKeyOrNull(): MacMappingKey? {
    val effectiveDigest = when (this) {
        is WithDigest -> digest
        is TruncatedMessageAuthenticationCode -> (inner as? WithDigest)?.digest
        else -> null
    }
    return MacMappingKey(
        digest = effectiveDigest,
        outputLength = outputLength,
    )
}

fun SymmetricEncryptionAlgorithm<*, *, *>.symmetricMappingKeyOrNull(): SymmetricMappingKey? = when (this) {
    is AesGcmAlgorithm -> SymmetricMappingKey(AesGcmSymmetricMappingKind, keySize)
    ChaCha20Poly1305Algorithm -> SymmetricMappingKey(ChaCha20Poly1305SymmetricMappingKind, keySize)
    else -> null
}

fun AsymmetricEncryptionAlgorithm.asymmetricEncryptionMappingKeyOrNull(): AsymmetricEncryptionMappingKey? =
    if (this is WithRsaEncryptionPadding) AsymmetricEncryptionMappingKey(padding) else null
