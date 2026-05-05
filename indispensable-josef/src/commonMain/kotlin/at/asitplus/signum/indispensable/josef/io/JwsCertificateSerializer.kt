package at.asitplus.signum.indispensable.josef.io

import at.asitplus.awesn1.serialization.DER
import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.Certificate
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

object JwsCertificateSerializer : TransformingSerializerTemplate<Certificate, ByteArray>(
    parent = ByteArrayBase64Serializer,
    encodeAs = DER::encodeToByteArray,
    decodeAs = { DER.decodeFromByteArray<Certificate>(it) } //workaround iOS compilation bug KT-71498
)
