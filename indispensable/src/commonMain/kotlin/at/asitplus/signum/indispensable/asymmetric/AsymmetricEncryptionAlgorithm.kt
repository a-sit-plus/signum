package at.asitplus.signum.indispensable.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration


sealed interface RSAPadding : Enumerable {
    @HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
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

    companion object : Enumeration<RSAPadding> {
        override val entries: List<RSAPadding> by lazy {
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
    ) : AsymmetricEncryptionAlgorithm {
        companion object {

            @HazardousMaterials("This is almost always insecure and can leak your private key!")
            val NoPadding = RSA(RSAPadding.NONE)

            @HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
            val Pkcs1Padding = RSA(RSAPadding.PKCS1)

            val OAEP = OAEPWith()
        }

        /** Pre-configured RSA algorithm instance with OAEP-SHAXXX  */
        class OAEPWith {
            val SHA1 = RSA(RSAPadding.OAEP.SHA1)
            val SHA256 = RSA(RSAPadding.OAEP.SHA256)
            val SHA384 = RSA(RSAPadding.OAEP.SHA384)
            val SHA512 = RSA(RSAPadding.OAEP.SHA512)
        }
    }

}
