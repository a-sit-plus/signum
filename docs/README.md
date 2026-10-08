# Building the Signum documentation

The manual embeds examples from the modules' `jvmTest`, `iosTest`, and `androidDeviceTest` sources, under a separate
`at.asitplus.signum.examples` package. Historical migration examples live in the independent `legacy-examples` JVM
project and use published Indispensable 3.26.0 / Supreme 0.16.0 dependencies.

Use the existing MkDocs environment, then run the documentation build from the repository root:

```shell
source ~/pyenv/mkdocs-material/bin/activate
./gradlew mkDocsSite
```

The build runs the public modules' JVM tests, the extensibility tests, and the isolated legacy tests before MkDocs
builds the site. It also rejects handwritten Kotlin fences and missing/duplicate snippet regions.
Android and iOS examples are checked by the existing platform CI runs; hardware interactions are not part of the JVM gate.

For the examples and snippet checks without generating the site, run `./gradlew docsTest`.
For legacy examples alone, run `./gradlew -p docs/legacy-examples test`.

Wrap the code to display in named `// --8<-- [start:subject-example]` and `// --8<-- [end:subject-example]` markers,
then reference `module/src/jvmTest/kotlin/at/asitplus/signum/examples/Example.kt:subject-example` from a Kotlin fence.
The snippet paths are relative to the repository root. Test the displayed behavior with assertions, and use the
same source for every page that demonstrates it. Material annotations belong in the source as `/* (1)! */` comments;
the corresponding numbered explanations follow the snippet in the manual.

The root CHANGELOG is copied during the build. Generated Dokka pages and the rendered site are not source files.
