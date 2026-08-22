package com.lightphone.passkey.server

import android.content.Context
import com.lightphone.passkey.cable.Qr
import com.lightphone.passkey.core.Base64Url
import com.lightphone.passkey.core.Credential
import com.lightphone.passkey.core.CredentialStore
import com.lightphone.passkey.core.PasskeyAuthenticator
import java.util.ArrayDeque
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The passkey session's live state, as served to the tool's status view. */
data class SessionState(
    /** "idle" | "running" | "pick" | "done" | "error" */
    val state: String = "idle",
    /** Recent status lines, newest last (capped). */
    val lines: List<String> = emptyList(),
    /** Short outcome ("Passkey created", "Signed in", "Stopped", …). */
    val summary: String? = null,
    /** Candidate user names while [state] == "pick" (a GetAssertion matched >1 credential). */
    val candidates: List<String> = emptyList(),
)

/**
 * Owns the caBLE hybrid session in the merged server module: parses the
 * scanned QR, runs the [HybridSession], and folds its log into a
 * [SessionState] the tool polls via GetSessionState. The authenticator's UV
 * gate launches [UvActivity] through [UvPrompt] (the tool runtime forbids
 * BiometricPrompt — UV lives here).
 */
object SessionManager {

    private const val MAX_LINES = 50

    private lateinit var appContext: Context
    private val _state = MutableStateFlow(SessionState())
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val lines = ArrayDeque<String>()
    private var session: HybridSession? = null
    /** Bumped on every start/stop; stale-session callbacks are ignored. */
    private var sessionId = 0L
    private var seenOk = false
    private var lastSummary: String? = null

    private val store by lazy { CredentialStore(appContext) }

    private val authenticator by lazy {
        PasskeyAuthenticator(
            store = store,
            uvGate = { title, subtitle, crypto ->
                UvPrompt.prompt(appContext, title, subtitle, crypto)
            },
            accountPicker = { _, candidates -> pendingPickAccount(candidates) },
            uvAvailable = { store.isUvAvailable() },
        )
    }

    // Pending account picker: the tool resolves it via PickAccount(index).
    // The deferred is replaced per pick; resolving with -1 cancels.
    private var pendingPick = CompletableDeferred<Int>()

    /** Suspends a GetAssertion that matched several credentials until the tool picks. */
    private suspend fun pendingPickAccount(candidates: List<Credential>): Credential? {
        pendingPick = CompletableDeferred()
        _state.value = SessionState(
            state = "pick", lines = lines.toList(), candidates = candidates.map { it.userName },
        )
        val index = pendingPick.await()
        _state.value = SessionState(state = "running", lines = lines.toList())
        return candidates.getOrNull(index)
    }

    /** Resolves a pending pick (index into the state's candidates); -1 cancels. */
    fun pickAccount(index: Int) {
        if (!pendingPick.isCompleted) pendingPick.complete(index)
    }

    private fun cancelPendingPick() {
        if (!pendingPick.isCompleted) pendingPick.complete(-1)
    }

    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /**
     * Starts a caBLE session from a scanned QR payload; returns an error
     * string (QR unparseable) or null when the session started.
     */
    fun start(qrPayload: String): String? {
        val qr = Qr.parse(qrPayload) ?: return "not a passkey QR (expected FIDO:/…)"
        session?.stop()
        session = null
        cancelPendingPick()
        sessionId++
        lines.clear()
        seenOk = false
        lastSummary = null
        _state.value = SessionState(state = "running")
        session = HybridSession(appContext, authenticator) { line -> log(sessionId, line) }
            .also { it.start(qr) }
        return null
    }

    /**
     * Stops a running session — or, from a finished one, resets the tool back
     * to the idle passkeys panel. Safe from any state (idle → idle).
     */
    fun stop() {
        cancelPendingPick()
        sessionId++
        session?.stop()
        session = null
        _state.value = SessionState(state = "idle", lines = lines.toList(), summary = "Stopped")
    }

    /** The stored passkeys (newest first), for the tool's list screen. */
    fun listCredentials(): List<Credential> =
        store.list().sortedByDescending { it.createdAt }

    /** Deletes a stored passkey by base64url credential id (Keystore key + row). */
    fun deleteCredential(credentialIdB64u: String) {
        store.delete(Base64Url.decode(credentialIdB64u))
    }

    private fun log(id: Long, line: String) {
        if (id != sessionId) return // stale session (superseded by a new start/stop)
        // Mirrored to logcat ("passkey") — the DesktopClient verification
        // path reads the outcome lines there; session-scoped, a few lines per
        // session, not a polling loop.
        android.util.Log.d("passkey", line)
        if (lines.size >= MAX_LINES) lines.removeFirst()
        lines.addLast(line)
        when {
            line.contains("MakeCredential OK") -> { seenOk = true; lastSummary = "Passkey created" }
            line.contains("GetAssertion OK") -> { seenOk = true; lastSummary = "Signed in" }
        }
        // The session is terminal when the tunnel fails or the desktop closes
        // it (after the ceremony). "shutdown from desktop" arrives before the
        // close but after any OK, so done wins over the pending close.
        val ended = line.startsWith("FAIL") ||
            line.startsWith("shutdown") ||
            line.startsWith("closed")
        if (ended) {
            // A dying session also releases any pending account pick (the
            // tool would otherwise wait forever on a pick that can't finish).
            cancelPendingPick()
            _state.value = SessionState(
                state = if (seenOk) "done" else "error",
                lines = lines.toList(),
                summary = lastSummary ?: line.removePrefix("FAIL: ").takeIf { line.startsWith("FAIL") },
            )
        } else {
            _state.value = SessionState(state = "running", lines = lines.toList())
        }
    }
}
