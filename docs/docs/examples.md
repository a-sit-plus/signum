# Signum Examples

This page demonstrates how to accomplish common tasks using _Signum_.

## Issuing Binding Certificates

!!! info  inline end
    This example requires the _Supreme_ KMP crypto provider. Only _Signum_-specifics are illustrated using code snippets.  
    We'll assume a JVM backend using _[WARDEN](https://github.com/a-sit-plus/warden)_ and trust anchors all set up correctly
    on the client apps.
A common pattern in a mobile client setting are so-called _binding certificates_ (or binding keys, but we'll stick to certificates here).
Just assume a bank with a mobile client application: Customers are typically issued an activation token out-of-band
(via mail, by the teller, …). This token is used to activate the app and transactions can then be authorized using biometrics.

This process works more or less as follows:

1. The client contacts the back-end to start the binding process
2. The back-end requests some out-of-band transmitted, personalized token to identify the customer
3. The user enters this information into the client app and the app transmits this information to the back-end.
4. The back-end sends a challenge to the client
5. The client creates a new public-private key pair, ideally using the challenge to also attest app, key, and the biometric authorization requirement (see [Attestation](supreme.md#attestation)).
       ```kotlin
       val signer = PlatformSigningProvider.createSigningKey("binding") {
         ec { curve = ECCurve.SECP_256_R_1 }
         hardware {
            backing = REQUIRED
            attestation { challenge = challengeFromServer }
            protection {
                factors { biometry = true }
            }
         }
       }.getOrElse { TODO("Handle error") } as Signer.Attestable<*>
       ```
6. The client creates and signs a CSR for the key, which includes the challenge (and, ideally, also an attestation proof)
      ```kotlin
      val tbsCSR = TbsCertificationRequest(
          subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
          publicKey = signer.publicKey,
          attributes = listOf(
              Pkcs10CertificationRequestAttribute(
                  // No OID is assigned for this; choose one!
                  attestationOid,
                                      // ↓↓↓ contains challenge ↓↓↓
                  Asn1String.UTF8(signer.attestation!!.jsonEncoded).encodeToTlv()
              )
          )
      )

      val csr = Pkcs10CertificationRequest(
          tbsCSR, X509SignatureAlgorithm.ES256,
          signer.sign(tbsCSR.encodeToDer()).signature.encodeToDer()
      )
      ```
7. The back-end verifies tha signature of the CSR, and validates the challenge (and attestation information, if present)
      ```kotlin
       X509SignatureAlgorithm.ES256.verifierFor(csr.tbsCsr.publicKey)
           .getOrElse { TODO("Handle error") }
           .verify(
               csr.tbsCsr.encodeToDer(),
               CryptoSignature.decodeFromDer(csr.signature)
           ).getOrElse { TODO("Abort here!") }

       val attestation =
           csr.tbsCsr.attributes?.firstOrNull { it.oid == attestationOid }
               ?.value?.first() ?: TODO("Abort here!")
      //TODO: feed attestation to WARDEN for verification
      ```
8. The back-end issues and signs a _binding certificate_ for the CSR, stores it to identify the client, and transmits it to the client.
       ```kotlin
       val tbsCrt = TbsCertificate(
         serialNumber = Random.nextBytes(16),
         signatureAlgorithm = X509SignatureAlgorithm.ES256,
         issuerName = backendIssuerName,
         validFrom = Asn1Time(Clock.System.now()),
         validUntil = Asn1Time(Clock.System.now() + VALIDITY),
         subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
         publicKey = ISSUER_KEY
       )

       val clientCertificate = X509Certificate(
         tbsCrt,
         signatureAlgorithm = X509SignatureAlgorithm.ES256,
         signer.sign(tbsCrt.encodeToDer()).signature
       )
       ```
9. The client stores the certificate.

To recap: This example shows how to
* instantiate a signer for a hardware-backed, biometry-protected, attested key
* instantiate a verifier
* create, sign and verify CSRs with a custom attribute
* extract a custom attribute from a CSR
* create, and sign certificates

# Create and Verify a JWT on the JVM

# Create and Verify a CWT on a Mobile Client

# Parse an X.509 CRL
_Signum_ currently has no built-in CRL type, nor does it support certificate validation, since this is a complex task.
In controlled settings, with a single root certificate signing all client certificates, however,
it is rather straight-forward, even when also considering revocation.
Assuming the root CA publishes CRLs and you have obtained one, you can parse it as follows: