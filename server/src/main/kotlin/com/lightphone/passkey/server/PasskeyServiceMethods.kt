package com.lightphone.passkey.server

import com.thelightphone.sdk.shared.LightResult
import com.thelightphone.sdk.shared.LightServiceMethod

/**
 * Implements the passkey methods on the embedded LightSdkService — the
 * server-side half of the tool model: the tool is a thin scanner/status UI
 * that calls these over the SDK binder; the caBLE session and the
 * authenticator (Keystore + UV) live here. Runs on a binder thread; nothing
 * here blocks on I/O beyond the session's own async work.
 */
object PasskeyServiceMethods {

    fun dispatch(methodId: String, payload: String?): LightResult<String> = when (methodId) {
        LightServiceMethod.StartPasskeySession.id -> {
            val request = LightServiceMethod.StartPasskeySession.decodeRequest(payload!!)
            val error = SessionManager.start(request.qrPayload)
            val response = LightServiceMethod.StartPasskeySession.Response(ok = error == null, error = error)
            LightResult.Success(LightServiceMethod.StartPasskeySession.encodeResponse(response))
        }

        LightServiceMethod.StopSession.id -> {
            SessionManager.stop()
            LightResult.Success(LightServiceMethod.StopSession.encodeResponse(Unit))
        }

        LightServiceMethod.GetSessionState.id -> {
            val s = SessionManager.state.value
            val response = LightServiceMethod.GetSessionState.Response(s.state, s.lines, s.summary)
            LightResult.Success(LightServiceMethod.GetSessionState.encodeResponse(response))
        }

        else -> LightResult.Error(LightResult.ErrorCode.Unknown, "unknown method $methodId")
    }
}
