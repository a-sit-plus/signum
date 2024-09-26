![indispensable-cosef](assets/cosef-dark-large.png#only-light) ![indispensable-cosef](assets/cosef-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable-cosef?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum.indispensable-cosef/)

# Indispensable COSE Data Structures

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent COSE data
types and utility functions. It comes with predefined JOSE algorithm identifiers and guaranteed correct
serialization, leveraging kotlinx.serialization.
There's really not much more to it; it's data structures with self-describing names that interop with
_Indispensable_ data classes such as `SignatureAlgorithm`, `CryptoSignature`,  and `CryptoPublicKey`.

Classes like `CborWebToken` come with `serialize()` and `deserialize()` functions, that take care of everything.
The preconfigured serializer ensuring compliant serialization of all COSE-related data structures is called `coseCompliantSerializer`.

!!! tip
      **Do check out the full API docs [here](dokka/indispensable-cosef/index.html)** to get an overview about all COSE-specific data types included!


## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it targets
the JVM, Android and iOS.

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.signum:indispensable-cosef:$version")
```
