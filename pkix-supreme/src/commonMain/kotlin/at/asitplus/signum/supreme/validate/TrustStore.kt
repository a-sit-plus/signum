package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.TrustStore

/**
 * The platform's **live** system trust store, or `null` when the platform exposes none (e.g.
 * browser/wasm sandboxes, where the runtime performs TLS itself and roots are not reachable).
 * Provided on a best-effort basis and may be incomplete.
 *
 * Unlike [at.asitplus.signum.indispensable.pki.BundledTrustStore] (a static, Apple-sourced snapshot
 * embedded at build time), this reflects the host's *current* trust configuration. A common default
 * is `systemTrustStore ?: BundledTrustStore`.
 */
@ExperimentalPkiApi
expect val systemTrustStore: TrustStore?
