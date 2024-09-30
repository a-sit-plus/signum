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
          tbsCSR,
          signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
          signer.sign(tbsCSR.encodeToDer()).signature.encodeToDer() //TODO handle error
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
         signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
         issuerName = backendIssuerName,
         validFrom = Asn1Time(Clock.System.now()),
         validUntil = Asn1Time(Clock.System.now() + VALIDITY),
         subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
         publicKey = ISSUER_KEY,
         extensions = listOf(
             // we want to indicate, that this client passed attestation checks
             X509CertificateExtension(
             attestedClientOid,
             critical = true,
             Asn1PrimitiveOctetString(byteArrayOf())
           )
         )
       )

       val clientCertificate = X509Certificate(
         tbsCrt,
         signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
         signer.sign(tbsCrt.encodeToDer()).signature
       )
       ```
9. The client stores the certificate.

To recap: This example shows how to
* instantiate a signer for a hardware-backed, biometry-protected, attested key
* instantiate a verifier
* create, sign and verify CSRs with a custom attribute
* extract a custom attribute from a CSR
* create, and sign a certificate with a custom critical extension

## Creating a Signed JSON Web Signature Object (`JwsSigned`)

!!! info  inline end
    This example requires the _Supreme_ KMP crypto provider and _Indispensable Josef_.

In this example, we'll start with an ephemeral P-256 signer: 

```kotlin
val signer = Signer.Ephemeral {
    ec { curve = ECCurve.SECP_256_R_1 }
}.getOrThrow() //TODO handle error properly
```

Next up, we'll create a header and payload:

```kotlin
val header = JwsHeader(
    algorithm = signer.signatureAlgorithm.toJwsAlgorithm().getOrThrow(),
    jsonWebKey = signer.publicKey.toJsonWebKey()
)
val payload = byteArrayOf(1, 3, 3, 7)
```

Since both header and payload are fed into the signature, we need to prepare this signature input:

```kotlin
val plainSignatureInput = JwsSigned.prepareJwsSignatureInput(header, payload)
```

Now, everything is ready to be signed:

```kotlin
val signature = signer.sign(plainSignatureInput.encodeToByteArray()).signature //TODO: handle error
JwsSigned(header, payload, signature, plainSignatureInput).serialize() // this we can verify on jwt.io 
```

As can be seen, a `JwsSigned` takes header, payload, signature, and the plain signature input as parameters.
The reason for keeping this fourth parameter is convenience and efficiency: For one, you need this input to serialize a
`JwsSigned`, so it would be a waste to discard it. After parsing a `JswSigned` from its serialized form, you also need the 
`plainSignatureInput` to verify everything was signed correctly.


## Creating a `CoseSigned` Object

!!! info  inline end
    This example requires the _Supreme_ KMP crypto provider and _Indispensable Cosef_.

In this example, we'll again start with an ephemeral P-256 signer:

```kotlin
val signer = Signer.Ephemeral {
    ec { curve = ECCurve.SECP_256_R_1 }
}.getOrThrow() //TODO handle error properly
```

Next up, we'll create a header and payload:

```kotlin
//set KID + algorithm
val protectedHeader = CoseHeader(
    algorithm = signer.signatureAlgorithm.toCoseAlgorithm().getOrElse { TODO() },
    kid = signer.publicKey.didEncoded.encodeToByteArray()
)

val payload = byteArrayOf(0xC, 0xA, 0xF, 0xE)
```

Both of these are signature inputs, so we'll construct a `CoseSignatureInput` to sign.

```kotlin
val signatureInput = CoseSignatureInput(
    contextString = "Signature1",
    protectedHeader = ByteStringWrapper(protectedHeader),
    externalAad = byteArrayOf(),
    payload = payload,
).serialize()
```


Now, everything is ready to be signed:

```kotlin
val signature = signer.sign(signatureInput).signature //TODO handle error

val coseSigned = CoseSigned(
    ByteStringWrapper(protectedHeader),
    unprotectedHeader = null,
    payload,
    signature
).serialize() // sadly, there's no cwt.io, but you can use cbor.me to explore the signed data
```

## Create and Parse a Custom-Tagged ASN.1 Structure

!!! info  inline end
    This example requires only the _Indispensable_ module.

When you come across a certain pattern more than once, you only encode and decode it once and recycle this code.
Still, it has to be done at least once. This example shows how to create a small, custom-tagged ASN.1 structure and shows how
it can be parsed and validated.

### Definitions

Let's say you are using ASN.1 as your wire format and you want to report the status about an operation.
The status message is an implicitly tagged ASN.1 structure with APPLICATION tag `1337` and sequence semantics.
It contains the number of times the operation was run, and a timestamp, which can be either relative (in whole seconds since the last operation)
or absolute (UTC Time). This relative/absolute flag uses the implicit APPLICATION tag `42` and the tuple of flag and time
is encoded into an ANS.1 OCTET STRING. This allows for two possible encodings, as illustrated below:

<table>
<tr>
<th>
Absolute Time
</th>
<th>
Relative Time
</th>
</tr>
<tr>
<td>

```asn1
Application 1337 (2 elem)
  INTEGER 1
  OCTET STRING (19 byte)
    Application 42 (1 byte) 00
    UTCTime 2024-09-30 18:11:59 UTC
```

</td>

<td>

```asn1
Application 1337 (2 elem)
  INTEGER 3
  OCTET STRING (7 byte)
    Application 42 (1 byte) FF
    INTEGER 39
```

</td>
</tr>
</table>

### Encoding

We'll be assuming absolute time to keep things simple.
Hence, the structure containing an absolute time can be created using the _Indispensable_ ASN.1 engine as follows:

```kotlin
val TAG_TIME_RELATIVE = 42uL withClass TagClass.APPLICATION

Asn1.Sequence {
    +Asn1.Int(1)
    +OctetStringEncapsulating {
        +(Bool(false) withImplicitTag TAG_TIME_RELATIVE)
        +Asn1Time(Clock.System.now())
    }
} withImplicitTag (1337uL withClass TagClass.APPLICATION) 
//                ↑ in reality this would be a constant ↑ 
```

The HEX-equivalent of this structure (which can be obtained by calling `.toDerHexString()`) is
[7F8A391802010104135F2A0100170D3234303933303138313135395A](https://lapo.it/asn1js/#f4o5GAIBAQQTXyoBABcNMjQwOTMwMTgxMTU5Wg).

### Parsing and Validating Tags

Basic parsing is straight-forward: You have DER-encoded bytes, and feed them into `AsnElement.parse()`.
Then you examine the first child to get the number of times the operation was carried out,
decode the first child of the OCTET STRING that follows to see of an UTC time follows or an int.

Usually, though (and especially when using implicit tags), you really want to verify those tags too.
Hence, parsing and properly validating is a bit more elaborate:

```kotlin
Asn1Element.parse(customSequence.derEncoded).asStructure().let { root -> 

  //↓↓↓ In reality, this would be a global constant
  val rootTag = Asn1Element.Tag(1337uL, tagClass = TagClass.APPLICATION, constructed = true)
  if (root.tag != rootTag) throw Asn1TagMismatchException(rootTag, root.tag)

  val numberOfOps = root.nextChild().asPrimitive().decodeToUInt()
  root.nextChild().asEncapsulatingOctetString().let { timestamp ->
    val isRelative = timestamp.nextChild().asPrimitive()
      .decode(TAG_TIME_RELATIVE) { Boolean.decodeFromAsn1ContentBytes(it) }

    val time = if (isRelative) timestamp.nextChild().asPrimitive().decodeToUInt()
    else timestamp.nextChild().asPrimitive().decodeToInstant()

    if (timestamp.hasMoreChildren() || root.hasMoreChildren())
      throw Asn1StructuralException("Superfluous Content")
      
    // Everything is parsed and validated
    TODO("Create domain object from $numberOfOps, $isRelative, and $time")
    }
}
```