# Supreme Multiplatform (JVM, Android, iOS) Demo App


![img.png](img.png)

This app showcases the _Supreme_ KMP Crypto provider on Android and on iOS. Demoing the JVM target would require additional configuration due to limitations of Kotlin.
It was decided to avoid this clutter for the demo app, since the Supreme test suite already showcases the JVM provider usage.

It is possible to generate key pairs, sign data, and verify the signature.

Generation of attestation statements is also supported, although on iOS, only P-256 keys can be attested due to platform constreaints.
The default JVM provider does not natively support the creation of attestation statements.

## Before running!
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



