package at.asitplus.signum.indispensable.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.SecretExposure


sealed interface RSAPadding {
    @HazardousMaterials("This padding Scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
    object PKCS1 : RSAPadding {
        override fun toString(): String = "PKCS1"
    }

    @HazardousMaterials("This is almost always insecure and can leak your private key!")
    object NONE : RSAPadding {
        override fun toString(): String = "NONE"
    }


    sealed class OAEP(val digest: Digest) : RSAPadding {
        object SHA1 : OAEP(Digest.SHA1)
        object SHA256 : OAEP(Digest.SHA256)
        object SHA384 : OAEP(Digest.SHA384)
        object SHA512 : OAEP(Digest.SHA512)

        override fun toString(): String = "OAEP_${digest.name}"
    }

    companion object {
        val entries: List<RSAPadding> by lazy {
            @OptIn(HazardousMaterials::class)
            listOf(PKCS1, NONE, OAEP.SHA1, OAEP.SHA256, OAEP.SHA384, OAEP.SHA512)
        }

        fun fromString(string: String) = entries.firstOrNull { it.toString() == string }
    }


}

sealed interface AsymmetricEncryptionAlgorithm {
    data class RSA(
        /** The padding to apply to the data. */
        val padding: RSAPadding
    ) : AsymmetricEncryptionAlgorithm

}
