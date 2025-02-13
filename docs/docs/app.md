---
hide:
  - navigation
---

# Supreme CMP Showcase App

<figure markdown="span">
![App Screenshot](assets/app.png){ width="300" }
</figure>


This app showcases the _Supreme_ KMP Crypto provider on JVM, Android and on iOS.
It is possible to generate key pairs, sign data, verify the signature, and demonstrate
key agreement ([souce code](https://github.com/a-sit-plus/signum/blob/main/demoapp/)).

Generation of attestation statements is also supported, although on iOS, only P-256 keys can be attested due to platform constraints.
The default JVM provider does not natively support the creation of attestation statements, so it is a NOOP there.

!!! bug inline end
    The Android OS has a bug related to key agreement in hardware. See [important remarks](features.md#android-key-agreement) on key agreement!

ECDH key agreement is also implemented across platforms.

Except for the JVM (because there is no system-wide keystore), the app relies only on multiplatform code.
Hence, everything is located in the common [App.kt](https://github.com/a-sit-plus/signum/blob/main/demoapp/composeApp/src/commonMain/kotlin/at/asitplus/cryptotest/App.kt).  
As can be seen, no activity passing and callbacks are required, even for biometric auth! Everything _just works_&copy; automagically…

## Building and Running the App

### Before running!
- check your system with [KDoctor](https://github.com/Kotlin/kdoctor)
- install JDK 17 on your machine
- add `local.properties` file to the project root and set a path to Android SDK there

### Android
To run the application on android device/emulator:
- open project in Android Studio and run imported android run configuration

To build the application bundle:
- run `./gradlew :composeApp:assembleDebug`
- find `.apk` file in `composeApp/build/outputs/apk/debug/composeApp-debug.apk`

### iOS
To run the application on iPhone device/simulator:
- Open `iosApp/iosApp.xcproject` in Xcode and run standard configuration
- Or use [Kotlin Multiplatform Mobile plugin](https://plugins.jetbrains.com/plugin/14936-kotlin-multiplatform-mobile) for Android Studio

**Attestation and biometric auth is not supported on the simulator!** Only Apple could fix this, but this is unlikely to ever happen.

## Functionality
This section explains the UI elements of the showcase app.
Since the app is especially aimed at demonstrating interactions with hardware-backed keystores on mobile devices
(i.e. `AndroidKeyStore` on Android and `SecureEnclave` on iOS), some of the UI elements do not make sense on the JVM.

!!! abstract winline end "Legend"
    1. Attestation toggle: Adds attestation information to the key. On iOS, this only works for P-256 keys and requires an Internet connection.
    2. Biometric auth selection: Makes key usage require biometric authentication if set. The app provides one of:
        * Disabled = no auth required
        * 0s = auth on every use
        * 10s = require reauthentication after 10 seconds
        * 20s = require reauthentication after 20 seconds
        * 60s = require reauthentication after 60 seconds
    3. Specify which key to generate (has no bearing on loading/deleting keys)
    4. _Generate_ a key according to the selected properties (see above). This will fail if a key has already been generated!
    5. _Load_ a previously generated key. This will fail if no key is present in hardware (i.e. none has been generated yet).
    6. _Delete_ the current key (if any). This is required prior to generating a new key!
    7. Current key display; shows the public key of the currently generated/loaded key.
    8. Signature input: This text field can be populated with text to be signed.
    9. _Sign_ the data present in the signature input text field using the current key
    10. Random, ephemeral key display: This text field is only visible, when loading/generating and EC key and contains a randomly-generated
    EC key, which is not hardware-backed. This key is used to demonstrate key agreement.
    11. ECDH key agreement button (only visible, when loading/generating and EC key): Performs an ECDH key agreement based on the current key in hardware and the random ephemeral key from above.
    The key agreement is performed in both "directions":
        1. Using the hardware-backed private key and the ephemeral public key from above. This may require biometric authentication, if set.
        2. Using the public part of the hardware-backed key and the private part of the ephemeral key from above. Never requires authentication,
        is unaffected by the [Android key agreement but](features.md#android-key-agreement), and is also available on lower Android versions.
    12. Shared secret display (only visible, when loading/generating and EC key): Displays the generated shared secrets from key agreement.
    13. Detached signature display: Displays the generated signature (after pushing Button%nbsp;9).
    14. _Verify_ the signature from _13_ on the data from _8_.
    15. Key attestation display: shows attestation data from a generated/loaded key (if any).

![App Legend](assets/legend.png){width="400"}

