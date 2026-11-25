package at.asitplus.cryptotest

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.layout.wrapContentSize
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Signature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.sign.RsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.dsl.PREFERRED
import at.asitplus.signum.dsl.attestation
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.dsl.factors
import at.asitplus.signum.dsl.hardware
import at.asitplus.signum.dsl.protection
import at.asitplus.signum.dsl.purposes
import at.asitplus.signum.dsl.rsa
import at.asitplus.signum.dsl.signer
import at.asitplus.signum.dsl.unlockPrompt
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.ECDSASigner
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.indispensable.sign.signature
import at.asitplus.signum.indispensable.sign.makeVerifier
import at.asitplus.signum.indispensable.sign.verify
import at.asitplus.cryptotest.theme.AppTheme
import at.asitplus.cryptotest.theme.LocalThemeIsDark
import at.asitplus.signum.indispensable.agree.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.randomKey
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.dsl.PlatformSignerConfigurationBase
import at.asitplus.signum.dsl.SignerConfiguration
import at.asitplus.signum.supreme.os.SigningProvider
import at.asitplus.signum.indispensable.sign.SignatureVerifier
import at.asitplus.signum.supreme.symmetric.decrypt
import at.asitplus.signum.supreme.symmetric.encrypt
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import io.ktor.util.encodeBase64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlin.random.Random
import kotlin.reflect.KProperty
import kotlin.time.Duration.Companion.seconds


/* because we also want it to work on the jvm;
you don't need this workaround for ios/android, just use PlatformSigningProvider directly */
expect val Provider: SigningProvider

const val ALIAS = "Bartschlüssel"
val SIGNER_CONFIG: (SignerConfiguration.() -> Unit) = {
    if (this is PlatformSignerConfigurationBase) {
        unlockPrompt {
            message = "We're signing a thing!"
            cancelText = "No! Stop!"
        }
    }
    rsa {
        padding = RsaAlgorithm.Padding.PKCS1
    }
}

@OptIn(DelicateCoroutinesApi::class)
val context = newSingleThreadContext("crypto").also { Napier.base(DebugAntilog()) }

private class getter<T>(private val fn: () -> T) {
    operator fun getValue(nothing: Nothing?, property: KProperty<*>): T = fn()
}

@OptIn(
    ExperimentalCoroutinesApi::class,
    SecretExposure::class
)
@Composable
internal fun App() {

    AppTheme {
        var attestation by remember { mutableStateOf(false) }
        var biometricAuth by remember { mutableStateOf(" Disabled") }
        val algos = mapOf(
            "ES256" to EcdsaAlgorithm.withSHA256,
            "ES384" to EcdsaAlgorithm.withSHA384,
            "ES512" to EcdsaAlgorithm.withSHA512,
            "RS1" to RsaAlgorithm(RsaAlgorithm.Padding.PKCS1, Digest.SHA1),
            "RS256" to RsaAlgorithm.withSHA256andPKCS1Padding,
            "RS384" to RsaAlgorithm.withSHA384andPKCS1Padding,
            "RS512" to RsaAlgorithm.withSHA512andPKCS1Padding
        )
        var keyAlgorithm by remember { mutableStateOf("ES256") }
        var inputData by remember { mutableStateOf("Foo") }
        var currentSigner by remember { mutableStateOf<Result<Signer>?>(null) }
        val currentKey by getter { currentSigner?.mapCatching(Signer::publicKey) }
        val currentKeyStr by getter {
            currentKey?.fold(
                onSuccess = {
                    it.toString()
                },
                onFailure = {
                    Napier.e("Key failed", it)
                    "${it::class.simpleName ?: "<unnamed>"}: ${it.message}"
                }) ?: "<none>"
        }
        val currentAttestation by getter { (currentSigner?.getOrNull() as? Signer.Attestable<*>)?.attestation }
        val currentAttestationStr by getter {
            currentAttestation?.jsonEncoded?.also { Napier.d { "Current Attestation: $it" } } ?: ""
        }
        val signingPossible by getter { currentKey?.isSuccess == true }
        var signatureData by remember { mutableStateOf<Result<Signature>?>(null) }
        var ephemeralKey by remember {
            mutableStateOf<KeyAgreementPrivateValue.ECDH?>(
                null
            )
        }
        var agreedKey by remember { mutableStateOf<Result<ByteArray>?>(null) }
        val signatureDataStr by getter {
            signatureData?.fold(onSuccess = Any::toString) {
                Napier.e("Signature failed", it)
                "${it::class.simpleName ?: "<unnamed>"}: ${it.message}"
            } ?: ""
        }
        val verifyPossible by getter { signatureData?.isSuccess == true }
        var verifyState by remember { mutableStateOf<Result<SignatureVerifier.Success>?>(null) }
        var encRT by remember { mutableStateOf<String?>(null) }
        val verifySucceededStr by getter {
            verifyState?.fold(onSuccess = {
                "Verify OK!"
            }, onFailure = {
                "${it::class.simpleName ?: "<unnamed>"}: ${it.message}"
            }) ?: "  "
        }
        var canGenerate by remember { mutableStateOf(true) }

        var genTextOverride by remember { mutableStateOf<String?>(null) }
        val genText by getter { genTextOverride ?: "Generate" }

        suspend fun genEphemeralKey() {
            ephemeralKey = (currentKey?.getOrNull() as? EcdsaPublicKey)?.let { key ->
                catchingUnwrapped { KeyAgreementPrivateValue.ECDH.Ephemeral(key.curve) }.getOrNull()
            }
            agreedKey = null
        }


        Column(
            modifier = Modifier.fillMaxSize().verticalScroll(ScrollState(0), enabled = true)
                .windowInsetsPadding(WindowInsets.safeDrawing)
        ) {

            Row(
                horizontalArrangement = Arrangement.Center
            ) {
                Text(
                    text = "Supreme Demo",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(
                        top = 16.dp,
                        start = 16.dp,
                        end = 16.dp,
                        bottom = 0.dp
                    )
                )

                Spacer(modifier = Modifier.weight(1.0f))

                var isDark by LocalThemeIsDark.current
                IconButton(
                    onClick = { isDark = !isDark }
                ) {
                    Icon(
                        modifier = Modifier.padding(8.dp).size(20.dp),
                        imageVector = if (isDark) Icons.Default.LightMode else Icons.Default.DarkMode,
                        contentDescription = null
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Row {
                    Text(
                        "Attestation",
                        modifier = Modifier.padding(top = 11.dp)
                    )
                    Checkbox(
                        checked = attestation,
                        modifier = Modifier.wrapContentSize(Alignment.TopStart).padding(0.dp),
                        onCheckedChange = {
                            attestation = it
                        })
                }
                Row {
                    Text(
                        "Biometric Auth",
                        modifier = Modifier.padding(
                            start = 0.dp,
                            top = 12.dp,
                            end = 4.dp,
                            bottom = 0.dp
                        )


                    )

                    var expanded by remember { mutableStateOf(false) }
                    Box(
                        modifier = Modifier.wrapContentSize(Alignment.TopStart).padding(top = 12.dp)
                            .background(MaterialTheme.colorScheme.primary)
                    ) {

                        Text(
                            biometricAuth,
                            modifier = Modifier.align(Alignment.BottomStart).width(78.dp)
                                .clickable(onClick = {
                                    expanded = true

                                }),
                            color = MaterialTheme.colorScheme.onPrimary

                        )
                        DropdownMenu(
                            expanded = expanded,
                            onDismissRequest = {
                                expanded = false
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            listOf(
                                " Disabled",
                                " 0s",
                                " 10s",
                                " 20s",
                                " 60s"
                            ).forEachIndexed { _, s ->
                                DropdownMenuItem(
                                    text = { Text(text = s) },
                                    onClick = {
                                        expanded = false
                                        biometricAuth = s
                                    })
                            }
                        }
                    }
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Key Type", modifier = Modifier.padding(horizontal = 16.dp))
                var expanded by remember { mutableStateOf(false) }
                val displayedKeySize by getter { (if (expanded) " ▲ " else " ▼ ") + keyAlgorithm }
                Box(
                    modifier = Modifier.fillMaxWidth().wrapContentSize(Alignment.TopStart)
                        .padding(horizontal = 16.dp).background(MaterialTheme.colorScheme.primary)
                ) {

                    Text(
                        displayedKeySize,
                        modifier = Modifier.fillMaxWidth().align(Alignment.TopStart)
                            .clickable(onClick = {
                                expanded = true
                            }),
                        color = MaterialTheme.colorScheme.onPrimary

                    )
                    DropdownMenu(
                        expanded = expanded,
                        onDismissRequest = {
                            expanded = false
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        algos.keys.forEach { algorithm ->
                            DropdownMenuItem(
                                text = { Text(text = algorithm) },
                                onClick = {
                                    keyAlgorithm = algorithm
                                    expanded = false
                                })
                        }
                    }
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Button(
                    enabled = canGenerate,
                    onClick = {
                        CoroutineScope(context).launch {
                            canGenerate = false
                            genTextOverride = "Creating…"
                            currentSigner = catchingUnwrapped {
                                Provider.createSigningKey(ALIAS) {

                                    when (val alg = algos.getValue(keyAlgorithm)) {
                                        is EcdsaAlgorithm -> {
                                            this@createSigningKey.ec {
                                                curve = alg.requiredCurve
                                                    ?: ECCurve.entries.find { it.nativeDigest == alg.digest }!!
                                                digests = setOf(alg.digest)
                                                purposes {
                                                    keyAgreement = true
                                                }
                                            }
                                        }

                                        is RsaAlgorithm -> {
                                            this@createSigningKey.rsa {
                                                digests = setOf(alg.digest)
                                                paddings = RsaAlgorithm.Padding.entries.toSet()
                                                bits = 1024
                                            }
                                        }

                                        else -> error("unreachable")
                                    }

                                    signer(SIGNER_CONFIG)

                                    val timeout = runCatching {
                                        biometricAuth.substringBefore("s").trim().toInt()
                                    }.getOrNull()

                                    if (attestation || timeout != null) {
                                        hardware {
                                            backing = PREFERRED
                                            if (attestation) {
                                                attestation {
                                                    challenge = Random.nextBytes(16)
                                                }
                                            }

                                            if (timeout != null) {
                                                protection {
                                                    this.timeout = timeout.seconds
                                                    factors {
                                                        biometry = true
                                                        deviceLock = true
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            verifyState = null

                            Napier.w { "created signing key! $currentSigner" }
                            Napier.w { "Signing possible: ${currentKey?.isSuccess}" }
                            canGenerate = true
                            genTextOverride = null

                            genEphemeralKey()
                        }
                    },
                    modifier = Modifier.padding(start = 16.dp)
                ) {
                    Text(genText)
                }

                Button(
                    enabled = canGenerate,
                    onClick = {
                        CoroutineScope(context).launch {
                            canGenerate = false
                            genTextOverride = "Loading…"
                            catchingUnwrapped { Provider.getSignerForKey(ALIAS, SIGNER_CONFIG) }.let {
                                Napier.w { "Priv retrieved from native: $it" }
                                currentSigner = it
                                verifyState = null
                            }

                            //just to check
                            //loadPubKey().let { Napier.w { "PubKey retrieved from native: $it" } }
                            canGenerate = true
                            genTextOverride = null
                            genEphemeralKey()
                        }
                    },
                    modifier = Modifier.padding(start = 16.dp, end = 16.dp)
                ) {
                    Text("Load")
                }

                Button(
                    enabled = canGenerate,
                    onClick = {
                        CoroutineScope(context).launch {
                            canGenerate = false
                            genTextOverride = "Deleting…"
                            catchingUnwrapped { Provider.deleteSigningKey(ALIAS) }
                                .onFailure { Napier.e("Failed to delete key", it) }
                            currentSigner = null
                            signatureData = null
                            verifyState = null
                            canGenerate = true
                            genTextOverride = null
                        }
                    },
                    modifier = Modifier.padding(end = 16.dp)
                ) {
                    Text("Delete")
                }

            }
            OutlinedTextField(
                value = currentKeyStr,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                minLines = 1,
                maxLines = 5,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                readOnly = true, onValueChange = {}, label = { Text("Current Key") })


            OutlinedTextField(
                value = inputData,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                enabled = true,
                minLines = 1,
                maxLines = 2,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                onValueChange = { inputData = it; verifyState = null },
                label = { Text("Data to be signed") })

            Button(
                onClick = {
                    Napier.w { "input: $inputData" }
                    Napier.w { "signingKey: $currentKey" }
                    CoroutineScope(context).launch {
                        val data = inputData.encodeToByteArray()
                        signatureData = catchingUnwrapped { currentSigner!!.getOrThrow().sign(data).signature }
                        verifyState = null
                    }
                },
                modifier = Modifier.padding(horizontal = 16.dp).fillMaxWidth(),
                enabled = signingPossible
            ) { Text("Sign") }

            if (signingPossible && (currentKey?.getOrNull() is EcdsaPublicKey)) {
                Napier.i { "Ephemeral key: $ephemeralKey" }
                Spacer(Modifier.height(8.dp))
                ephemeralKey?.let { ephemeralKey ->
                    OutlinedTextField(
                        value = ephemeralKey.publicValue.toString(),
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        minLines = 1,
                        textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                        readOnly = true,
                        onValueChange = {},
                        label = { Text("Random faux-external key for ECDH") })
                    Button(
                        onClick = {
                            Napier.w { "input: $inputData" }
                            Napier.w { "signingKey: $currentKey" }
                            CoroutineScope(context).launch {

                                agreedKey = catchingUnwrapped {
                                    (currentSigner!!.getOrThrow() as ECDSASigner).keyAgreement(ephemeralKey.publicValue)
                                }
                                Napier.i {
                                    "ECDH Key of ext_piv + hardware-backed_pub: ${
                                        agreedKey?.getOrNull()?.encodeBase64()
                                    }"
                                }

                                Napier.i {
                                    "ECDH Key of ext_pub + hardware-backed_priv: ${
                                        agreedKey?.getOrNull()?.encodeBase64()
                                    }"
                                }
                            }

                        },
                        modifier = Modifier.padding(horizontal = 16.dp).fillMaxWidth(),
                    ) { Text("Perform ECDH key agreement") }
                }

                if (agreedKey != null) {
                    OutlinedTextField(
                        value =
                        "Computed from ext_pub + hardware-backed_priv:\n" + agreedKey?.map { it.encodeBase64() }
                            ?.getOrElse { it.message ?: it::class.simpleName ?: "" },
                        modifier = Modifier.fillMaxWidth().padding(16.dp),
                        minLines = 1,
                        textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                        readOnly = true,
                        onValueChange = {},
                        label = { Text("Agreed-upon secret") })
                }
            }

            if (signatureData != null) {
                OutlinedTextField(
                    value = signatureDataStr,
                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                    minLines = 1,
                    textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                    readOnly = true, onValueChange = {}, label = { Text("Detached Signature") })
            }

            if (verifyPossible) {
                Button(
                    onClick = {
                        CoroutineScope(context).launch {
                            val signer = currentSigner!!.getOrThrow()
                            val data = inputData.encodeToByteArray()
                            val sig = signatureData!!.getOrThrow()
                            verifyState = catchingUnwrapped { signer.makeVerifier().verify(data, sig) }
                        }
                    },

                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    enabled = verifyPossible
                ) {
                    Text("Verify")
                }
            }


            if (verifyState != null) {
                OutlinedTextField(
                    value = verifySucceededStr,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    minLines = 1,
                    textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                    readOnly = true,
                    onValueChange = {},
                    label = { Text("Verification Result") })
            }

            if (currentAttestation != null) {
                OutlinedTextField(
                    value = currentAttestationStr,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    minLines = 1,
                    textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                    readOnly = true,
                    onValueChange = {},
                    label = { Text("Key Attestation") })
            }

            Button(
                onClick = {
                    CoroutineScope(context).launch {
                        encRT=""
                        listOf(
                            SymmetricEncryptionAlgorithm.AES_256.CBC.HMAC.SHA_256,
                            SymmetricEncryptionAlgorithm.AES_256.GCM,
                            SymmetricEncryptionAlgorithm.ChaCha20Poly1305
                        ).forEach { alg ->
                            val k = alg.randomKey()
                            val data = Random.nextBytes(1023)
                            val ciph = k.encrypt(data)
                            val dec= ciph.decrypt(k)
                            encRT+="ALG: ${alg.name}:\n\ndata: ${data.encodeBase64()}"
                            encRT+="\n\nencrypted: ${ciph.encryptedData.encodeBase64()}"
                            encRT+="\n\ndecrypted: ${dec.encodeBase64()}\n\n------------\n\n"
                        }
                    }
                },

                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            ) {
                Text("Symmetric roundtrip")
            }


            if (encRT != null) {
                OutlinedTextField(
                    value = encRT?:"",
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    minLines = 1,
                    textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                    readOnly = true,
                    onValueChange = {},
                    label = { Text("Encryption Round Trip") })
            }
        }
    }
}
