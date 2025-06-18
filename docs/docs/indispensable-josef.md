![indispensable-josef](assets/josef-dark-large.png#only-light) ![indispensable-josef](assets/josef-light-large.png#only-dark)

[![Maven Central](https://img.shields.io/maven-central/v/at.asitplus.signum/indispensable-josef?label=maven-central)](https://mvnrepository.com/artifact/at.asitplus.signum.indispensable-josef/)

# Indispensable JOSE Data Structures

This [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html) library provides platform-independent JOSE data
types and utility functions. It comes with predefined JOSE algorithm identifiers and guaranteed correct
serialization, leveraging kotlinx.serialization.
There's really not much more to it; it's data structures with self-describing names that interop with
_Indispensable_ data classes such as `SignatureAlgorithm`, `CryptoSignature`,  and `CryptoPublicKey`.

Classes like `JsonWebToken` come with `serialize()` and `deserialize()` functions, since their encoded representation is not a valid JSON string.
The preconfigured serializer ensuring compliant serialization of all JOSE-related data structures is called `joseCompliantSerializer`.

!!! tip
    **Do check out the full API docs [here](dokka/indispensable-josef/index.html)** to get an overview about all JOSE-specific data types included!

## Using it in your Projects

This library was built for [Kotlin Multiplatform](https://kotlinlang.org/docs/multiplatform.html). Currently, it supports all KMP targets except `watchosDeviceArm64`.

Simply declare the desired dependency to get going:

```kotlin 
implementation("at.asitplus.signum:indispensable-josef:$version")
```
