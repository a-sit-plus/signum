package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.pki.Pkcs10CertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.X509Certificate

typealias PublicKey = CryptoPublicKey
typealias PrivateKey = CryptoPrivateKey
typealias Signature = CryptoSignature
typealias Certificate = X509Certificate
typealias CertificateInfo = TbsCertificate
typealias CertificationRequest = Pkcs10CertificationRequest
typealias CertificationRequestInfo = TbsCertificationRequest
