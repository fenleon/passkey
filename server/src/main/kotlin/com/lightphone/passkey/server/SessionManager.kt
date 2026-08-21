package com.lightphone.passkey.server

import android.content.Context
import com.lightphone.passkey.cable.Qr
import com.lightphone.passkey.core.CredentialStore
import com.lightphone.passkey.core.PasskeyAuthenticator
import java.util.ArrayDeque
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** The passkey session's live state, as served to the tool's status view. */
data class SessionState(
    /** "idle" | "running" | "done" | "error" */
    val state: String = "idle",
    /** Recent status lines, newest last (capped). */
    val lines: List<String> = emptyList(),
    /** Short outcome ("Passkey created", "Signed in", "Stopped", …). */
    val summary: String? = null,
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

    private val authenticator by lazy {
        PasskeyAuthenticator(CredentialStore(appContext)) { title, subtitle, crypto ->
            UvPrompt.prompt(appContext, title, subtitle, crypto)
        }
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
        sessionId++
        lines.clear()
        seenOk = false
        lastSummary = null
        _state.value = SessionState(state = "running")
        session = HybridSession(appContext, authenticator) { line -> log(sessionId, line) }
            .also { it.start(qr) }
        return null
    }

    fun stop() {
        if (_state.value.state != "running") return
        sessionId++
        session?.stop()
        session = null
        _state.value = SessionState(state = "idle", lines = lines.toList(), summary = "Stopped")
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
