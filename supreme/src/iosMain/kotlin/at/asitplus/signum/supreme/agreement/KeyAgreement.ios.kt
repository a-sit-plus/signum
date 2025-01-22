package at.asitplus.signum.supreme.agreement

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.internals.corecall
import at.asitplus.signum.internals.takeFromCF
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.toSecKey
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import platform.Foundation.NSData
import platform.Security.SecKeyRef

@OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
internal fun performKeyAgreement(privateKey: SecKeyRef?, publicKey: CryptoPublicKey) =
    memScoped {
        val pub = toSecKey(publicKey)
        corecall {
            platform.Security.SecKeyCopyKeyExchangeResult(
                privateKey,
                platform.Security.kSecKeyAlgorithmECDHKeyExchangeStandard,
                pub,
                parameters = null,
                error
            )
        }.takeFromCF<NSData>().toByteArray()
    }
