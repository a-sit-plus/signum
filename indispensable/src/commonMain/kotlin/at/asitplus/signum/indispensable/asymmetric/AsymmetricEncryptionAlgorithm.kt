package at.asitplus.signum.indispensable.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.Digest


sealed interface RSAPadding {
    object PKCS1: RSAPadding
    @HazardousMaterials("This is almost always insecure and can leak your private key!")
    object NONE: RSAPadding

    sealed class OAEP(val digest: Digest): RSAPadding{
        object SHA1: OAEP(Digest.SHA1)
        object SHA256: OAEP(Digest.SHA256)
        object SHA384: OAEP(Digest.SHA384)
        object SHA512: OAEP(Digest.SHA512)
    }
}

sealed interface AsymmetricEncryptionAlgorithm {
    data class RSA(
        /** The padding to apply to the data. */
        val padding: RSAPadding
    ) : AsymmetricEncryptionAlgorithm

}
