package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.pki.BundledTrustStore

import at.asitplus.signum.indispensable.pki.SignumPkix

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.collections.shouldNotBeEmpty

@OptIn(ExperimentalPkiApi::class)
val systemTruststoreTest by matrixSuite {
    SignumPkix.install()
    "Trust stores" - {
        // The bundled store is build-time embedded and must be present on every platform.
        "bundled store is not empty" {
            BundledTrustStore.anchors.shouldNotBeEmpty()
        }
        // The system store may be null (e.g. browser/wasm); when present it should carry anchors.
        "system store, when present, is not empty" {
            systemTrustStore?.let {
                it.anchors.shouldNotBeEmpty()
                println("System TrustStore loaded with ${it.anchors.size} trust anchors")
            }
        }
    }
}