package at.asitplus.signum.indispensable.josef.io

import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.toAsn1

object JwsCertificateSerializer : TransformingSerializerTemplate<Certificate, ByteArray>(
    parent = ByteArrayBase64Serializer,
    encodeAs = { it.toAsn1.DER() },
    decodeAs = { Certificate.fromAsn1(it) } //workaround iOS compilation bug KT-71498
)
