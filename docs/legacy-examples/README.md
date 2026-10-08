# Published legacy examples

Run from the repository root:

    ./gradlew -p docs/legacy-examples test

This independent Kotlin/JVM build resolves Indispensable 3.26.0 and Supreme 0.16.0 only from Maven Central.
It has no project dependencies, mavenLocal repository, included builds or source substitution. Its five
JUnit tests execute historical signing and its failure representation, DER encoding, compact JWS and COSE Sign1 examples. Named regions
in `LegacyExamples.kt` are embedded in the migration manual.
