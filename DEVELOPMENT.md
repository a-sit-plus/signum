# Development

## Publishing

Create a GPG key with `gpg --gen-key`, and export it with `gpg --keyring secring.gpg --export-secret-keys > ~/.gnupg/secring.gpg`. Be sure to publish it with `gpg --keyserver keyserver.ubuntu.com --send-keys <your-key-id>`. See also the information in the [Gradle docs](https://docs.gradle.org/current/userguide/signing_plugin.html).

Create a user token for your Nexus account on <https://s01.oss.sonatype.org/> (in your profile) to use as `sonatypeUsername` and `sonatypePassword`.

Configure your `~/.gradle/gradle.properties`:

```properties
signing.keyId=<last-8-chars>
signing.password=<private-key-password>
signing.secretKeyRingFile=<path-of-your-secring>
sonatypeUsername=<user-token-name>
sonatypePassword=<user-token-password>
```

To run the pipeline from GitHub, export your GPG key with `gpg --export-secret-keys --armor <keyid> | tee <keyid>.asc` and set the following environment variables:

```shell
ORG_GRADLE_PROJECT_signingKeyId=<last-8-chars>
ORG_GRADLE_PROJECT_signingKey=<ascii-armored-key>
ORG_GRADLE_PROJECT_signingPassword=<private-key-password>
ORG_GRADLE_PROJECT_sonatypeUsername=<user-token-name>
ORG_GRADLE_PROJECT_sonatypePassword=<user-token-password>
```

Actually, these environment variables are read from the repository secrets configured on Github.

Publish with:

```shell
./gradlew clean publishToSonatype
```

To also release the artifacts to Maven Central run:

```shell
./gradlew clean publishToSonatype closeAndReleaseSonatypeStagingRepository
```

To publish locally for testing, one can skip the signing tasks:

```shell
./gradlew clean publishToMavenLocal -x signJvmPublication -x signKotlinMultiplatformPublication -x signIosArm64Publication -x signIosSimulatorArm64Publication -x signIosX64Publication
```
