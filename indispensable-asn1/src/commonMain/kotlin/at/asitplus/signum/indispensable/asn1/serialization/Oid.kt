package at.asitplus.signum.indispensable.asn1.serialization

import at.asitplus.signum.indispensable.asn1.Identifiable
import kotlinx.serialization.SerialInfo
import kotlin.reflect.KClass

interface OidToken : Identifiable


@SerialInfo
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS)
annotation class OidIdentified(val token: KClass<out OidToken>)