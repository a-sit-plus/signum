package at.asitplus.signum.indispensable.josef.io

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.Certificate

object JwsCertificateSerializer : TransformingSerializerTemplate<Certificate, ByteArray>(
    parent = ByteArrayBase64Serializer,
    encodeAs = Certificate::encodeToDer,
    decodeAs = { Certificate.decodeFromDer(it) } //workaround iOS compilation bug KT-71498
)
