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
import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.RSAPadding
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.SpecializedSignatureAlgorithm
import at.asitplus.signum.indispensable.X509SignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.dsl.PREFERRED
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.makeVerifier
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.cryptotest.theme.AppTheme
import at.asitplus.cryptotest.theme.LocalThemeIsDark
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.jsonEncoded
import at.asitplus.signum.supreme.agreement.keyAgreement
import at.asitplus.signum.supreme.asKmmResult
import at.asitplus.signum.supreme.os.PlatformSignerConfigurationBase
import at.asitplus.signum.supreme.os.PlatformSigningKeyConfigurationBase
import at.asitplus.signum.supreme.os.SignerConfiguration
import at.asitplus.signum.supreme.os.SigningProvider
import at.asitplus.signum.supreme.sign.Verifier
import io.github.aakira.napier.DebugAntilog
import io.github.aakira.napier.Napier
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.newSingleThreadContext
import kotlin.io.encoding.Base64
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
        padding = RSAPadding.PKCS1
    }
}

val context = newSingleThreadContext("crypto").also { Napier.base(DebugAntilog()) }

private class getter<T>(private val fn: () -> T) {
    operator fun getValue(nothing: Nothing?, property: KProperty<*>): T = fn()
}

@OptIn(ExperimentalStdlibApi::class, ExperimentalCoroutinesApi::class, kotlin.io.encoding.ExperimentalEncodingApi::class)
@Composable
internal fun App() {

    AppTheme {
        var attestation by remember { mutableStateOf(false) }
        var biometricAuth by remember { mutableStateOf(" Disabled") }
        val algos = listOf(
            X509SignatureAlgorithm.ES256,
            X509SignatureAlgorithm.ES384,
            X509SignatureAlgorithm.ES512,
            X509SignatureAlgorithm.RS1,
            X509SignatureAlgorithm.RS256,
            X509SignatureAlgorithm.RS384,
            X509SignatureAlgorithm.RS512
        )
        var keyAlgorithm by remember {
            mutableStateOf<SpecializedSignatureAlgorithm>(
                X509SignatureAlgorithm.ES256
            )
        }
        var inputData by remember { mutableStateOf("Foo") }
        var currentSigner by remember { mutableStateOf<KmmResult<Signer>?>(null) }
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
        var signatureData by remember { mutableStateOf<KmmResult<CryptoSignature>?>(null) }
        val signatureDataStr by getter {
            signatureData?.fold(onSuccess = Any::toString) {
                Napier.e("Signature failed", it)
                "${it::class.simpleName ?: "<unnamed>"}: ${it.message}"
            } ?: ""
        }
        val verifyPossible by getter { signatureData?.isSuccess == true }
        var verifyState by remember { mutableStateOf<KmmResult<Verifier.Success>?>(null) }
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
                    Checkbox(checked = attestation,
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
                                DropdownMenuItem(text = { Text(text = s) },
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
                        algos.forEachIndexed { index, s ->
                            DropdownMenuItem(text = { Text(text = s.toString()) },
                                onClick = {
                                    keyAlgorithm = algos[index]
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
                            currentSigner = Provider.createSigningKey(ALIAS) {
                                when (val alg = keyAlgorithm.algorithm) {
                                    is SignatureAlgorithm.ECDSA -> {
                                        this@createSigningKey.ec {
                                            curve = alg.requiredCurve
                                                ?: ECCurve.entries.find { it.nativeDigest == alg.digest }!!
                                            digests = setOf(alg.digest)
                                        }
                                    }

                                    is SignatureAlgorithm.RSA -> {
                                        this@createSigningKey.rsa {
                                            digests = setOf(alg.digest)
                                            paddings = RSAPadding.entries.toSet()
                                            bits = 1024
                                        }
                                    }

                                    else -> error("unreachable")
                                }

                                if (this is PlatformSigningKeyConfigurationBase) {
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
                            Provider.getSignerForKey(ALIAS, SIGNER_CONFIG).let {
                                Napier.w { "Priv retrieved from native: $it" }
                                currentSigner = it
                                verifyState = null
                            }

                            //just to check
                            //loadPubKey().let { Napier.w { "PubKey retrieved from native: $it" } }
                            canGenerate = true
                            genTextOverride = null
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
                            Provider.deleteSigningKey(ALIAS)
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
            OutlinedTextField(value = currentKeyStr,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                minLines = 1,
                maxLines = 5,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                readOnly = true, onValueChange = {}, label = { Text("Current Key") })


            OutlinedTextField(value = inputData,
                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                enabled = true,
                minLines = 1,
                maxLines = 2,
                textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                onValueChange = { inputData = it; verifyState = null },
                label = { Text("Data to be signed") })
            Row(modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween) {

                Button(
                    onClick = {

                        Napier.w { "input: $inputData" }
                        Napier.w { "signingKey: $currentKey" }
                        CoroutineScope(context).launch {
                            val data = inputData.encodeToByteArray()
                            currentSigner!!
                                .transform { it.sign(data).asKmmResult() }
                                .also { signatureData = it; verifyState = null }
                        }

                    },

                    modifier = Modifier.padding(horizontal = 16.dp),
                    enabled = signingPossible
                ) {
                    Text("Sign")
                }

                Button(
                    onClick = {

                        Napier.w { "input: $inputData" }
                        Napier.w { "signingKey: $currentKey" }
                        CoroutineScope(context).launch {
                            val alg= keyAlgorithm.algorithm as SignatureAlgorithm.ECDSA
                            val eph= Signer.Ephemeral {
                               ec {
                                            curve = alg.requiredCurve
                                                ?: ECCurve.entries.find { it.nativeDigest == alg.digest }!!
                                            digests = setOf(alg.digest)

                                }
                            }.getOrThrow()
                            val pub = eph.publicKey as CryptoPublicKey.EC
                            Napier.i { "Got Pubkey: $pub" }
                            val agreed= pub.keyAgreement( currentSigner!!.getOrThrow() as Signer.ECDSA).getOrThrow()
                            Napier.i { "AGREED1: ${Base64.encodeToByteArray(agreed)}" }
                            val agreed2 = ( currentSigner!!.getOrThrow() as Signer.ECDSA).keyAgreement(pub).getOrThrow()
                            Napier.i { "AGREED2: ${Base64.encodeToByteArray(agreed2)}" }
                        }

                    },

                    modifier = Modifier.padding(horizontal = 16.dp),
                   // enabled = keyAlgorithm is SignatureAlgorithm.ECDSA
                ) {
                    Text("ECDH")
                }
            }

            if (signatureData != null) {
                OutlinedTextField(value = signatureDataStr,
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
                            signer.makeVerifier()
                                .transform { it.verify(data, sig) }
                                .also { verifyState = it }
                        }
                    },

                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    enabled = verifyPossible
                ) {
                    Text("Verify")
                }
            }

            if (verifyState != null) {
                OutlinedTextField(value = verifySucceededStr,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    minLines = 1,
                    textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                    readOnly = true,
                    onValueChange = {},
                    label = { Text("Verification Result") })
            }

            if (currentAttestation != null) {
                OutlinedTextField(value = currentAttestationStr,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
                    minLines = 1,
                    textStyle = TextStyle.Default.copy(fontSize = 10.sp),
                    readOnly = true,
                    onValueChange = {},
                    label = { Text("Key Attestation") })
            }
        }
    }
}
