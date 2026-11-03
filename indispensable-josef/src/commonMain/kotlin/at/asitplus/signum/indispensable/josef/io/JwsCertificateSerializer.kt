package at.asitplus.signum.indispensable.josef.io

import at.asitplus.signum.Signum
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.pki.Certificate

object JwsCertificateSerializer : TransformingSerializerTemplate<Certificate, ByteArray>(
    parent = ByteArrayBase64Serializer,
    encodeAs = { Signum.Der.encodeToByteArray(it) },
    decodeAs = { Signum.Der.decodeFromByteArray<Certificate>(it) } //workaround iOS compilation bug KT-71498
)
