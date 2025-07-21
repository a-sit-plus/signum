# Signum Examples

This page demonstrates how to accomplish common tasks using _Signum_.

## Creating a Signed JSON Web Signature Object (`JwsSigned`)

!!! info  inline end
    This example requires the _Supreme_ KMP crypto provider and _Indispensable Josef_.

In this example, we'll start with an ephemeral P-256 signer: 

```kotlin
val signer = Signer.Ephemeral {
    ec { curve = ECCurve.SECP_256_R_1 }
}.getOrThrow() //TODO handle error
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
val signature = signer.sign(plainSignatureInput).signature //TODO: handle error
JwsSigned(header, payload, signature, plainSignatureInput).serialize() // this we can verify on jwt.io 
```

As can be seen, a `JwsSigned` takes header, payload, signature, and the plain signature input as parameters.
The reason for keeping this fourth parameter is convenience and efficiency: For one, you need this input to serialize a
`JwsSigned`, so it would be a waste to discard it. After parsing a `JswSigned` from its serialized form, you also need the 
`plainSignatureInput` to verify everything was signed correctly.

## Verifying a `JwsSigned` Object
Verifying a singed JSON web token is usually a straight-forward affair:
1. Parse the string and check if a sensible algorithm is set
2. Extract the public key from the header
3. Check the trust of the key (depends on the application at hand)
4. Verify the signature
5. Check timing-related and other constraints

```kotlin
//parse serialized JWS
val jwsObject = JwsSigned.deserialize(jws)

//check if a sensible algorithm is set
val jwsAlgorithm = jwsObject.header.algorithm

//JWS is very permissive, so we need to check that the alg makes sense
require(jwsAlgorithm is JwsAlgorithm.Signature) { "Algorithm not supported: $jwsAlgorithm" }

//establishing trust is out of scope; assuming a map of trusted public keys
val publicKey = trustedPublicKeys[jwsObject.header.keyId] ?: TODO("Fail on untrusted key")

//Create  verifier instance
val verifier = jwsAlgorithm.verifierFor(publicKey).getOrThrow()

//Verify cryptographically
val verified = verifier.verify(jwsObject.plainSignatureInput, jwsObject.signature).isSuccess

//Now we know the JWS holds up **cryptographically**

//TODO check the following for temporal validity
jwsObject.header.issuedAt
jwsObject.header.expiration

//TODO check any other constraints
```

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

Both of these are signature inputs, so we can construct the signature input:

```kotlin
val signatureInput = CoseSigned.prepareCoseSignatureInput(
    protectedHeader = protectedHeader,
    payload = payload,
    externalAad = byteArrayOf()
)
```

Now, everything is ready to be signed:

```kotlin
val signature = signer.sign(signatureInput).signature //TODO handle error

CoseSigned(
    protectedHeader = ByteStringWrapper(protectedHeader),
    unprotectedHeader = unprotectedHeader,
    payload = payload,
    signature = signature
)
// sadly, there's no cwt.io, but you can use cbor.me to explore the signed data
```

## Create and Parse a Custom-Tagged ASN.1 Structure

!!! info inline end
    This example requires only the _Indispensable_ module.

This example illustrates how to encapsulate a custom ASN.1 encoding scheme to make it reusable and composable.

### Definitions

Let's say you are using ASN.1 as your wire format for interoperability with different frameworks and languages.
This particular example demonstrates how log messages, i.e. the status of an operation, maybe from a smartcard, are sent off-device.

!!! note inline end
    Such constraints may seem artificial, but when bandwidth is low, a compact representation is key.

A log message is an implicitly tagged ASN.1 structure with APPLICATION tag `26` and sequence semantics.
It contains the number of times an operation was run, and a timestamp, which can be either relative (in whole seconds since the last operation)
or absolute (UTC Time).
This relative/absolute flag uses the implicit APPLICATION tag `42` and the tuple of flag and time
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
Application 26 (2 elem)
  INTEGER 1
  OCTET STRING (19 byte)
    Application 42 (1 byte) 00
    UTCTime 2024-09-30 18:11:59 UTC
```

</td>

<td>

```asn1
Application 26 (2 elem)
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
} withImplicitTag (26uL withClass TagClass.APPLICATION) 
//                ↑ in reality this would be a constant ↑ 
```

The HEX-equivalent of this structure (which can be obtained by calling `.toDerHexString()`) is
[7F8A391802010104135F2A0100170D3234303933303138313135395A](https://lapo.it/asn1js/#f4o5GAIBAQQTXyoBABcNMjQwOTMwMTgxMTU5Wg).

### Parsing and Validating Tags

Basic parsing is straight-forward: You have DER-encoded bytes, and feed them into `AsnElement.parse()`.
In this example, you examine the first child to get the number of times the operation was carried out;
then, you decode the first child of the OCTET STRING that follows to decide how to decode the second child.

Usually, though (and especially when using implicit tags), you really want to verify those tags too.
Hence, parsing and properly validating is a bit more elaborate. The use of `decodeRethrowing`,
by default, ensures that all elements have been parsed, such that no trailing elements can be overlooked:

```kotlin linenums="1"
Asn1Element.parse(customSequence.derEncoded).asStructure().decodeRethrowing {

  //↓↓↓ In reality, this would be a global constant; the same as in the previous snippet ↓↓↓
  val rootTag = Asn1Element.Tag(26uL, tagClass = TagClass.APPLICATION, constructed = true)
  containingStructure.assertTag(rootTag) //throws on tag mismatch

  val numberOfOps = next().asPrimitive().decodeToUInt()
  next().asEncapsulatingOctetString().decodeRethrowing {
    val isRelative = next().asPrimitive()
      .decodeToBoolean(TAG_TIME_RELATIVE)

    val time = if (isRelative) next().asPrimitive().decodeToUInt()
    else next().asPrimitive().decodeToInstant()

    // Everything is parsed and validated
    TODO("Create domain object from $numberOfOps, $isRelative, and $time")
  }
}
```

The above snippet performs the following validations:

1. Line 5 asserts the tag of the root structure
2. Line 7 ensures that the first child is an ASN.1 primitive tagged as INT, containing an unsigned integer
3. Line 8 execution successfully guarantees that the second child is indeed an ASN.1 OCTET STRING encapsulating
another ASN.1 structure.
4. Lines 9-10 verify that the first child contained in the ASN.1 OCTET STRING
    * is an ASN.1 primitive
    * tagged with `TAG_TIME_RELATIVE`
    * containing an ASN.1 boolean
5. Line 12 ensures that the next child is an ASN.1 primitive, encoding an unsigned integer (in case an `UInt` is expected)
6. Line 13 tackles the alternative and ensures that the next child contains a properly encoded ASN.1 time

## Issuing Binding Certificates

!!! info  inline end
    This example requires the _Supreme_ KMP crypto provider. Only _Signum_-specifics are illustrated using code snippets.

We'll assume a JVM backend using _[WARDEN](https://github.com/a-sit-plus/warden)_ and trust anchors all set up correctly
on the client apps.
A common pattern in a mobile client setting in the context of banking or eID are so-called _binding certificates_ (or binding keys, but we'll stick to certificates here).
Just assume a bank with a mobile client application: Customers are typically issued an activation token out-of-band
(via mail, by the teller, …). This token is used to activate the app and transactions can then be authorized using biometrics.

In settings as critical as eID and banking, the service operator typically wants to ensure that only uncompromised clients
may access a service. To ensure this, the example described here relies on attestation.

This process works more or less as follows:

1. The client contacts the back-end to start the binding process
2. The back-end authenticates the binding request, identifying the customer. This could be a traditional authentication process, some out-of-band personalized token, etc.
3. The user enters this information into the client app and the app transmits this information to the back-end.
4. The back-end sends a challenge to the client
5. The client creates a new public-private key pair, using the challenge to also attest app, key, and the biometric authorization requirement (see [Attestation](supreme.md#attestation)).
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
}.getOrElse { TODO("Handle error") }
```
6. The client creates and signs a CSR for the key, which includes the challenge and an attestation proof
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

//extension function producing a signed CSR
val csr = signer.sign(tbsCSR).getOrElse { TODO("handle error") }
```
7. The back-end verifies the signature of the CSR, and validates the challenge and attestation information
```kotlin
X509SignatureAlgorithm.ES256.verifierFor(csr.tbsCsr.publicKey)
  .getOrElse { TODO("Handle error") }
  .verify(
    csr.tbsCsr.encodeToDer(),
    CryptoSignature.decodeFromDer(csr.signature)
  ).getOrElse { TODO("Abort here!") }

val attestation =
  csr.tbsCsr.attributes.firstOrNull { it.oid == attestationOid }
    ?.value?.first() ?: TODO("Abort here!")
//TODO: feed attestation to WARDEN for verification
```
8. The back-end issues and signs a _binding certificate_ for the CSR, and transmits it to the client.
```kotlin
val tbsCrt = TbsCertificate(
  serialNumber = Random.nextBytes(16),
  signatureAlgorithm = signer.signatureAlgorithm.toX509SignatureAlgorithm().getOrThrow(),
  issuerName = backendIssuerName,
  validFrom = Asn1Time(Clock.System.now()),
  validUntil = Asn1Time(Clock.System.now() + VALIDITY),
  subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8("client")))),
  publicKey = csr.tbsCsr.publicKey, //client public key
  extensions = listOf(
    // we want to indicate, that this client passed attestation checks
    X509CertificateExtension(
      attestedClientOid,
      critical = true,
      Asn1OctetString(byteArrayOf())
    )
  )
)

val clientCertificate = signer.sign(tbsCrt).getOrElse { TODO("handle error") }
```
9. The client stores the certificate.

To recap: This example shows how to
* instantiate a signer for a hardware-backed, biometry-protected, attested key
* instantiate a verifier
* create, sign and verify CSRs with a custom attribute
* extract a custom attribute from a CSR
* create, and sign a certificate with a custom critical extension