package at.asitplus.signum.indispensable.asymmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.AlgorithmRegistry
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration


interface RSAPadding : Enumerable {
    @HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
    object PKCS1 : RSAPadding {
        override fun toString(): String = "PKCS1"
    }

    @HazardousMaterials("This is almost always insecure and can leak your private key!")
    object NONE : RSAPadding {
        override fun toString(): String = "NONE"
    }


    open class OAEP(val digest: Digest) : RSAPadding {
        object SHA1 : OAEP(Digest.SHA1)
        object SHA256 : OAEP(Digest.SHA256)
        object SHA384 : OAEP(Digest.SHA384)
        object SHA512 : OAEP(Digest.SHA512)

        override fun toString(): String = "OAEP_${digest.name}"
    }

    companion object : Enumeration<RSAPadding> {
        @OptIn(HazardousMaterials::class)
        private val builtIns: List<RSAPadding> by lazy {
            listOf(
                AlgorithmRegistry.registerAsymmetricRsaPadding(PKCS1),
                AlgorithmRegistry.registerAsymmetricRsaPadding(NONE),
                AlgorithmRegistry.registerAsymmetricRsaPadding(OAEP.SHA1),
                AlgorithmRegistry.registerAsymmetricRsaPadding(OAEP.SHA256),
                AlgorithmRegistry.registerAsymmetricRsaPadding(OAEP.SHA384),
                AlgorithmRegistry.registerAsymmetricRsaPadding(OAEP.SHA512)
            )
        }

        override val entries: List<RSAPadding>
            get() {
                builtIns
                return AlgorithmRegistry.asymmetricRsaPaddings
            }

        fun fromString(string: String) = entries.firstOrNull { it.toString() == string }
    }


}

interface AsymmetricEncryptionAlgorithm {
    open class RSA(
        /** The padding to apply to the data. */
        val padding: RSAPadding
    ) : AsymmetricEncryptionAlgorithm {
        override fun equals(other: Any?): Boolean = other is RSA && padding == other.padding

        override fun hashCode(): Int = padding.hashCode()

        override fun toString(): String = "RSA($padding)"

        companion object {

            @HazardousMaterials("This is almost always insecure and can leak your private key!")
            val NoPadding = AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(RSA(RSAPadding.NONE))

            @HazardousMaterials("This padding scheme is vulnerable to Bleichenbacher's attack. Use only with legacy application where you absolutely must")
            val Pkcs1Padding = AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(RSA(RSAPadding.PKCS1))

            val OAEP = OAEPWith()
        }

        /** Pre-configured RSA algorithm instance with OAEP-SHAXXX  */
        class OAEPWith {
            val SHA1 = AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(RSA(RSAPadding.OAEP.SHA1))
            val SHA256 = AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(RSA(RSAPadding.OAEP.SHA256))
            val SHA384 = AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(RSA(RSAPadding.OAEP.SHA384))
            val SHA512 = AlgorithmRegistry.registerAsymmetricEncryptionAlgorithm(RSA(RSAPadding.OAEP.SHA512))
        }
    }

}
