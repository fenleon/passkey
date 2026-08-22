package com.lightphone.passkey.app

import android.Manifest
import android.util.Log
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import com.thelightphone.sdk.ui.LightTopBar
import com.thelightphone.sdk.ui.LightTopBarCenter
import com.thelightphone.sdk.ui.gridUnitsAsDp
import com.thelightphone.sdk.ui.lightClickable
import java.security.SecureRandom
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

class PasskeyViewModel : LightViewModel<Unit>() {

    val session = MutableStateFlow<LightServiceMethod.GetSessionState.Response?>(null)
    val startError = MutableStateFlow<String?>(null)
    val passkeys = MutableStateFlow<List<LightServiceMethod.CredentialInfo>>(emptyList())

    private var pollJob: Job? = null

    override fun onScreenShow(screen: SimpleLightScreen<Unit>) {
        super.onScreenShow(screen)
        loadPasskeys()
        poll()
    }

    /** The stored passkeys for the idle panel (newest first). */
    fun loadPasskeys() {
        viewModelScope.launch {
            passkeys.value = callRemoteServiceMethod(LightServiceMethod.ListPasskeys, Unit)
                .getOrNull()?.credentials ?: emptyList()
        }
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

    /** Resolves a pending account pick; -1 cancels the sign-in (the server answers CTAP denied). */
    fun pickAccount(index: Int) {
        viewModelScope.launch {
            callRemoteServiceMethod(LightServiceMethod.PickAccount, LightServiceMethod.PickAccount.Request(index))
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
                // "pick" is a live state too — the account picker's outcome
                // (PickAccount) is reported by a later poll, not here.
                if (s.state != "running" && s.state != "pick") {
                    // Terminal — refresh the idle passkeys panel (a ceremony
                    // may have registered a new one).
                    loadPasskeys()
                    break
                }
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
        val passkeys by viewModel.passkeys.collectAsState()
        val permissionLauncher = rememberPermissionRequestLauncher(Manifest.permission.CAMERA)

        LightTheme(colors = themeColors) {
            if (scanning) {
                LightQrCodeScanner(
                    title = "Scan Passkey QR",
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
                    passkeys = passkeys,
                    onScan = { scanning = true },
                    onStop = viewModel::stop,
                    onAutoQr = viewModel::autoQr,
                    onOpenPasskey = { credential ->
                        navigateTo(screenFactory = { PasskeysDetailsScreen(it, credential) }) { deleted ->
                            if (deleted == true) viewModel.loadPasskeys()
                        }
                    },
                    onPick = viewModel::pickAccount,
                    onBackToList = viewModel::stop,
                )
            }
        }
    }
}

@Composable
private fun PasskeyContent(
    session: LightServiceMethod.GetSessionState.Response?,
    startError: String?,
    passkeys: List<LightServiceMethod.CredentialInfo>,
    onScan: () -> Unit,
    onStop: () -> Unit,
    onAutoQr: () -> Unit,
    onOpenPasskey: (LightServiceMethod.CredentialInfo) -> Unit,
    onPick: (Int) -> Unit,
    onBackToList: () -> Unit,
) {
    val state = session?.state ?: "idle"
    val lines = session?.lines ?: emptyList()
    val candidates = session?.candidates ?: emptyList()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(LightThemeTokens.colors.background)
    ) {
        // The app heading lives in the top bar (like a normal tool header).
        // A finished session keeps its back arrow here too (returns to the
        // panel); all other states just show the centered title.
        LightTopBar(
            leftButton = if (state == "done" || state == "error") {
                LightBarButton.LightIcon(
                    icon = LightIcons.BACK,
                    onClick = onBackToList,
                    contentDescription = "Back to Passkeys",
                )
            } else {
                null
            },
            center = LightTopBarCenter.Text(text = "Passkey"),
        )

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
                    )
                }

                state == "idle" -> {
                    if (passkeys.isEmpty()) {
                        LightText(
                            text = "No passkeys yet.",
                            variant = LightTextVariant.Copy,
                        )
                    } else {
                        LightScrollView(modifier = Modifier.fillMaxSize()) {
                            passkeys.forEach { credential ->
                                Column(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .lightClickable { onOpenPasskey(credential) }
                                        .padding(vertical = 1.2f.gridUnitsAsDp())
                                ) {
                                    LightText(
                                        text = credential.userName,
                                        variant = LightTextVariant.Copy,
                                    )
                                    LightText(
                                        text = "(${credential.rpId})",
                                        variant = LightTextVariant.Fine,
                                    )
                                }
                            }
                        }
                    }
                }

                state == "pick" -> {
                    // A GetAssertion matched several passkeys for the same site
                    // — pick the account to sign in as (the server suspends the
                    // ceremony until PickAccount resolves it).
                    LightText(
                        text = "Sign in as",
                        variant = LightTextVariant.Heading,
                        modifier = Modifier.padding(bottom = 1f.gridUnitsAsDp()),
                    )
                    candidates.forEachIndexed { index, name ->
                        LightText(
                            text = name,
                            variant = LightTextVariant.Copy,
                            modifier = Modifier
                                .fillMaxWidth()
                                .lightClickable { onPick(index) }
                                .padding(vertical = 1.2f.gridUnitsAsDp()),
                        )
                    }
                    if (candidates.isEmpty()) {
                        LightText(
                            text = "No accounts to choose from.",
                            variant = LightTextVariant.Copy,
                            lighten = true,
                        )
                    }
                }

                else -> {
                    LightText(
                        text = when (state) {
                            "running" -> "Signing in…"
                            "done" -> session?.summary ?: "Done"
                            // e.g. "UV unavailable — no secure lock on this device"
                            "error" -> session?.summary ?: "Couldn't sign in"
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
        // button for the primary command (SCAN / STOP / CANCEL), right slot =
        // debug auto-QR (dev-only, remove for a release), left slot empty.
        LightBottomBar(
            items = listOf(
                null,
                when (state) {
                    "pick" -> LightBarButton.Text(
                        text = "CANCEL",
                        onClick = { onPick(-1) },
                        contentDescription = "Cancel sign-in",
                    )
                    "running" -> LightBarButton.Text(
                        text = "STOP",
                        onClick = onStop,
                        contentDescription = "Stop session",
                    )
                    else -> LightBarButton.Text(
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
