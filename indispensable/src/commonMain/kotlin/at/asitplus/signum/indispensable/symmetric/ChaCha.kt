package at.asitplus.signum.indispensable.symmetric

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.chaCha20Poly1305
import at.asitplus.signum.indispensable.AlgorithmRegistry
import at.asitplus.signum.indispensable.misc.bit


object ChaCha20Poly1305Algorithm :
    StreamCipher<AuthCapability.Authenticated.Integrated, NonceTrait.Required, KeyType.Integrated>(),
    SymmetricEncryptionAlgorithm.Authenticated.Integrated<NonceTrait.Required>,
    SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated> {
    override val authTagSize = 128u.bit
    override val nonceSize = 96u.bit
    override val name: String = "ChaCha20-Poly1305"
    override fun toString() = name
    override val keySize = 256u.bit
    override val oid = KnownOIDs.chaCha20Poly1305
}
