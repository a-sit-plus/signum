package at.asitplus.signum.supreme

import at.asitplus.signum.indispensable.ECCurve

@JsExport
@JsName("someAPI")
fun someApi(foo:String ):String {
    return ECCurve.SECP_256_R_1.order.toString()
}