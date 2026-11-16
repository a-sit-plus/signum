package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.attributes.PkixAttributeTypeAndValueProvider

private val initializePkix by lazy {
    ServiceLoader.register<PolicyQualifierAsn1Provider>(BuiltinPolicyQualifiers)
    ServiceLoader.register<OtherNameAsn1Provider>(BuiltinOtherNames)
    ServiceLoader.register<CertificateExtensionProvider>(PkixAsn1Provider)
    ServiceLoader.register<GeneralNameFormatProvider>(PkixAsn1Provider)

    ServiceLoader.register<AttributeTypeAndValueProvider>(PkixAttributeTypeAndValueProvider)
}

/**
 * Install the PKIX representation and semantic attribute providers.
 * Custom providers register afterward. No contextual ASN.1 serializers are installed.
 */
fun Signum.installPkix() { initializePkix }

/** The chain ordered from trust anchor to leaf (reverse of the conventional leaf-first order). */
val CertificateChain.validationPath: CertificateChain get() = reversed()
