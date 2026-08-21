package com.lightphone.passkey.app

import android.Manifest
import android.util.Log
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewModelScope
import com.lightphone.passkey.cable.Qr
import com.lightphone.passkey.cable.toHex
import com.thelightphone.sdk.InitialScreen
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.SimpleLightScreen
import com.thelightphone.sdk.callRemoteServiceMethod
import com.thelightphone.sdk.checkPermission
import com.thelightphone.sdk.rememberPermissionRequestLauncher
import com.thelightphone.sdk.shared.LightServiceMethod
import com.thelightphone.sdk.shared.getOrNull
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightBottomBar
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightQrCodeScanner
import com.thelightphone.sdk.ui.LightScrollView
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.LightTheme
import com.thelightphone.sdk.ui.LightThemeController
import com.thelightphone.sdk.ui.LightThemeTokens
import com.thelightphone.sdk.ui.gridUnitsAsDp
import java.security.SecureRandom
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class PasskeyViewModel : LightViewModel<Unit>() {

    val session = MutableStateFlow<LightServiceMethod.GetSessionState.Response?>(null)
    val startError = MutableStateFlow<String?>(null)

    private var pollJob: Job? = null

    override fun onScreenShow(screen: SimpleLightScreen<Unit>) {
        super.onScreenShow(screen)
        poll()
    }

    fun startSession(qrPayload: String) {
        viewModelScope.launch {
            startError.value = null
            val result = callRemoteServiceMethod(
                LightServiceMethod.StartPasskeySession,
                LightServiceMethod.StartPasskeySession.Request(qrPayload),
            ).getOrNull()
            if (result != null && !result.ok) {
                startError.value = result.error ?: "couldn't start the session"
            } else {
                poll()
            }
        }
    }

    fun stop() {
        viewModelScope.launch {
            callRemoteServiceMethod(LightServiceMethod.StopSession, Unit)
            poll()
        }
    }

    /**
     * Debug/test entry (the JVM DesktopClient verification path): generate a
     * desktop-style QR key and start a session with it, like the pre-conversion
     * HybridActivity's auto-QR button. The key is logged for DesktopClient's
     * args (the advert/tunnel id come from the server's own session log).
     */
    fun autoQr() {
        val qrKey = ByteArray(48).also { SecureRandom().nextBytes(it) }
        val payload = Qr.encode(qrKey)
        Log.d("passkey", "auto QR key (for DesktopClient): ${qrKey.toHex()}")
        startSession(payload)
    }

    /** Polls the session state while it is active; stops once it is terminal. */
    private fun poll() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch {
            while (true) {
                val s = callRemoteServiceMethod(LightServiceMethod.GetSessionState, Unit).getOrNull()
                    ?: break
                session.value = s
                if (s.state != "running") break
                delay(POLL_MS)
            }
        }
    }

    private companion object {
        const val POLL_MS = 400L
    }
}

/**
 * The Passkey tool: scan the desktop's passkey QR (or use the debug auto-QR
 * button), then stream the caBLE hybrid session's status. The session itself
 * runs in the merged server module (StartPasskeySession/GetSessionState over
 * the SDK binder); UV prompts are the server's own activity.
 */
@InitialScreen
class PasskeyScreen(sealedActivity: SealedLightActivity) : LightScreen<Unit, PasskeyViewModel>(sealedActivity) {

    override val viewModelClass: Class<PasskeyViewModel> = PasskeyViewModel::class.java

    override fun createViewModel(): PasskeyViewModel = PasskeyViewModel()

    @Composable
    override fun Content() {
        val themeColors by LightThemeController.colors.collectAsState()
        var scanning by remember { mutableStateOf(false) }
        val session by viewModel.session.collectAsState()
        val startError by viewModel.startError.collectAsState()
        val permissionLauncher = rememberPermissionRequestLauncher(Manifest.permission.CAMERA)

        LightTheme(colors = themeColors) {
            if (scanning) {
                LightQrCodeScanner(
                    title = "Scan passkey QR",
                    onScanned = { value: String ->
                        scanning = false
                        viewModel.startSession(value)
                    },
                    onBack = { scanning = false },
                    checkCameraPermission = {
                        Result.success(
                            checkPermission(Manifest.permission.CAMERA).getOrNull()
                                ?.permissionResult == LightServiceMethod.GetPermission.Result.Granted
                        )
                    },
                    launchCameraPermissionRequest = { permissionLauncher?.launch() },
                )
            } else {
                PasskeyContent(
                    session = session,
                    startError = startError,
                    onScan = { scanning = true },
                    onStop = viewModel::stop,
                    onAutoQr = viewModel::autoQr,
                )
            }
        }
    }
}

@Composable
private fun PasskeyContent(
    session: LightServiceMethod.GetSessionState.Response?,
    startError: String?,
    onScan: () -> Unit,
    onStop: () -> Unit,
    onAutoQr: () -> Unit,
) {
    val state = session?.state ?: "idle"
    val lines = session?.lines ?: emptyList()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(LightThemeTokens.colors.background)
    ) {
        // Top spacer of the side-gutter size (no-text top bar for this
        // single-purpose tool — the SDK provides back navigation).
        Spacer(Modifier.height(2f.gridUnitsAsDp()))

        Column(
            modifier = Modifier
                .padding(horizontal = 2f.gridUnitsAsDp())
                .weight(1f)
        ) {
            when {
                startError != null -> {
                    LightText(
                        text = "Couldn't sign in",
                        variant = LightTextVariant.Heading,
                        modifier = Modifier.padding(bottom = 1f.gridUnitsAsDp()),
                    )
                    LightText(
                        text = startError,
                        variant = LightTextVariant.Copy,
                        lighten = true,
                    )
                }

                state == "idle" -> {
                    // No title: the toolbox already labels the tool (Library
                    // pattern — "the app name is redundant on a single-purpose
                    // device").
                    LightText(
                        text = "Scan a passkey QR from your computer to sign in.",
                        variant = LightTextVariant.Copy,
                        lighten = true,
                    )
                }

                else -> {
                    LightText(
                        text = when (state) {
                            "running" -> "Signing in…"
                            "done" -> session?.summary ?: "Done"
                            else -> "Couldn't sign in"
                        },
                        variant = LightTextVariant.Heading,
                        modifier = Modifier.padding(bottom = 1f.gridUnitsAsDp()),
                    )
                    if (lines.isNotEmpty()) {
                        LightScrollView(modifier = Modifier.fillMaxSize()) {
                            lines.forEach { line ->
                                LightText(
                                    text = line,
                                    variant = LightTextVariant.Fine,
                                    lighten = true,
                                    modifier = Modifier.padding(vertical = 0.2f.gridUnitsAsDp()),
                                )
                            }
                        }
                    }
                }
            }
        }

        // Bottom bar: the native 3-slot grammar — centered full-height text
        // button for the primary command, right slot = debug auto-QR
        // (dev-only, remove for a release), left slot empty.
        LightBottomBar(
            items = listOf(
                null,
                if (state == "running") {
                    LightBarButton.Text(
                        text = "STOP",
                        onClick = onStop,
                        contentDescription = "Stop session",
                    )
                } else {
                    LightBarButton.Text(
                        text = "SCAN",
                        onClick = onScan,
                        contentDescription = "Scan passkey QR",
                    )
                },
                LightBarButton.LightIcon(
                    icon = LightIcons.ADD,
                    onClick = onAutoQr,
                    contentDescription = "Debug auto QR",
                ),
            )
        )
    }
}
