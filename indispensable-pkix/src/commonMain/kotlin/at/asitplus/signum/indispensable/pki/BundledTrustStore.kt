@file:OptIn(ExperimentalStdlibApi::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.decodeFromDer

/**
 * A portable, build-time-embedded set of CA trust anchors, available on **every** platform that
 * ships `indispensable-pkix` — independent of any OS trust store, so there is always one at the
 * ready (browser/wasm sandboxes and bare containers included).
 *
 * ## Provenance — where these roots come from (read before relying on this)
 * The anchors are **Apple's** published CA set, embedded **verbatim** from Apple's open-source
 * *PKITrustStore* distribution:
 * - **Repository:** https://github.com/apple-oss-distributions/security_certificates
 * - **Pinned version (git tag):** `security_certificates-55349.40.11` — set by the
 *   `appleTrustStoreRef` Gradle property in the root `gradle.properties`.
 * - **Files:** every DER certificate (the `.cer` files) under `certificates/roots/` in that
 *   archive, hex-encoded into the generated `bundledRoots` list by the `generateBundledRootsSource`
 *   task in `indispensable-pkix/build.gradle.kts` at build time.
 *
 * ## Caveats
 * - **Static snapshot.** Frozen at the pinned tag; it does **not** track later OS trust-store
 *   updates, additions, or — importantly — **removals/distrusts**. Refresh by bumping
 *   `appleTrustStoreRef` and rebuilding.
 * - **Apple's trust decisions, not the host's.** On platforms with a real OS store
 *   (JVM/Android/…), prefer the live `systemTrustStore` (provided by `pkix-supreme`) and fall back
 *   to this only when none exists: `systemTrustStore ?: BundledTrustStore`.
 * - **Unconstrained roots.** Per-certificate OS trust settings (EKU scoping, partial distrust) are
 *   not represented; every embedded certificate is treated as a fully-trusted root.
 */
object BundledTrustStore : TrustStore {
    override val anchors: Set<TrustAnchor> by lazy {
        bundledRoots.map { TrustAnchor.Certificate(Certificate.decodeFromDer(it.hexToByteArray())) }.toSet()
    }
}
