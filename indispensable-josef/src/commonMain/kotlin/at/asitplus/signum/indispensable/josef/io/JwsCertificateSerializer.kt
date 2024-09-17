package at.asitplus.signum.indispensable.josef.io

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.X509Certificate

object JwsCertificateSerializer : TransformingSerializerTemplate<X509Certificate, ByteArray>(
    parent = ByteArrayBase64Serializer,
    encodeAs = X509Certificate::encodeToDer,
    decodeAs = { X509Certificate.decodeFromDer(it) } //workaround iOS compilation bug
)
