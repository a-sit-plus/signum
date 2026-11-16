package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.attributes.*

private val initializePkix by lazy {
    at.asitplus.signum.ServiceLoader.register<PolicyQualifierAsn1Provider>(BuiltinPolicyQualifiers)
    at.asitplus.signum.ServiceLoader.register<OtherNameAsn1Provider>(BuiltinOtherNames)
    Signum.register(PkixAsn1Provider)

    Signum.register(PkixAttributeTypeAndValueProvider)
}

/**
 * Install the PKIX representation and semantic attribute providers.
 * Custom providers register afterward. No contextual ASN.1 serializers are installed.
 */
fun Signum.installPkix() { initializePkix }

/** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
val CertificateChain.validationPath: CertificateChain get() = reversed()
