package at.asitplus.signum.indispensable

import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.pki.TbsCertificate

/** Compatibility for existing TbsCertificate signing consumers. */
fun TbsCertificate.encodeToDer(der: Der = DER): ByteArray =
    der.encodeToByteArray(TbsCertificateX509Serializer, this)
