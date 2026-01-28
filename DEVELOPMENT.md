# Development

Signum maintains two primary branches - [main](https://github.com/a-sit-plus/signum/tree/main) and [development](https://github.com/a-sit-plus/signum/tree/development).
`development` will always be strictly ahead of `main`. The two will never diverge.

Development of features is done in feature branches, which are based on `development`.
Pull requests will be used to merge finished features from their feature branch into `development`.
Each pull request will result in a single squashed feature commit on `development`, which references the original pull request.
**Pull requests must never be merged into `main`**, since doing so would cause `main` and `development` to diverge.

## Built-In Preflight Checks
This project ensures that Android and Apple targets are disabled when the host does not support it.
This means the Android Gradle Plugin is not even enabled and Android sources are not wired unless an Android SDK is correctly wired.
`disableAppleTargets` can be set either through environment variable or `local.properties`. The Android SDK can be wired into this project by all supported means

> [!WARNING]  
> When including Signum as part of a composite build and not using environment variables to setup an Android SDK or to enable/disable apple targets,
> make sure that local.properties with the correct settings is also present inside the **Signum** project directory in addition to the root project's!

## Release process

Both `main` and `development` are branch-protected against direct commits.
When finalizing a new release version (with `main` catching up to `development`), proceed as follows.
If any of these steps fail unexpectedly, please consult with your fellow developers instead of making potentially-breaking changes to the Git tree.

1. Create a new feature pull request against `development`, which updates `CHANGELOG.md` (removing the "NEXT" marker) and `gradle.properties` (to the release version).
2. Merge this pull request as usual.
3. Create a pull request from `development` against `main`. **Do not merge this pull request using the GitHub UI**, since doing so [breaks](https://stackoverflow.com/questions/60597400/how-to-do-a-fast-forward-merge-on-github) the linear relationship between `main` and `development`.
4. Once this pull request has been approved, **manually** merge it:
```shell
# make sure your local copy of the remote state is up-to-date
git fetch origin

# switch to your local main branch
git checkout main

# make sure your local main branch matches the remote main branch
git reset --hard origin/main 

# update your local main branch to the development branch without creating a merge commit
git merge --ff-only origin/development

# push your local main branch to the remote
git push origin main
```
5. GitHub recognizes that your push is closing the pull request that you created, and will permit it despite the branch protection rule.
6. Create a new tag for the release
7. Publish the release
8. Create a new feature pull request against `development`, which adds the next snapshot version to `CHANGELOG.md` and `gradle.properties`.
9. Merge this pull request as usual.

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

## Creating a new release

Create a release branch and do the usual commits, i.e. setting the version number and so on. Push it to Github. Run the workflow "Build iOS Framework", and attach the artefacts to the release info page on GitHub. Use the link from there to update the [Swift Package](https://github.com/a-sit-plus/swift-package-signum), modifying `Package.swift` and entering the URLs. The checksum is the output of `sha256sum *framework.zip`.
