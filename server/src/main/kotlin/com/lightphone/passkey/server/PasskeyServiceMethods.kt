package com.lightphone.passkey.server

import com.lightphone.passkey.core.Base64Url
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
            val response = LightServiceMethod.GetSessionState.Response(
                state = s.state,
                lines = s.lines,
                summary = s.summary,
                candidates = s.candidates,
            )
            LightResult.Success(LightServiceMethod.GetSessionState.encodeResponse(response))
        }

        LightServiceMethod.ListPasskeys.id -> {
            val response = LightServiceMethod.ListPasskeys.Response(
                SessionManager.listCredentials().map {
                    LightServiceMethod.CredentialInfo(
                        credentialId = com.lightphone.passkey.core.Base64Url.encode(it.credentialId),
                        rpId = it.rpId,
                        userName = it.userName,
                        createdAt = it.createdAt,
                        lastUsedAt = it.lastUsedAt,
                    )
                }
            )
            LightResult.Success(LightServiceMethod.ListPasskeys.encodeResponse(response))
        }

        LightServiceMethod.DeletePasskey.id -> {
            val request = LightServiceMethod.DeletePasskey.decodeRequest(payload!!)
            SessionManager.deleteCredential(request.credentialId)
            LightResult.Success(LightServiceMethod.DeletePasskey.encodeResponse(Unit))
        }

        LightServiceMethod.PickAccount.id -> {
            val request = LightServiceMethod.PickAccount.decodeRequest(payload!!)
            SessionManager.pickAccount(request.index)
            LightResult.Success(LightServiceMethod.PickAccount.encodeResponse(Unit))
        }

        else -> LightResult.Error(LightResult.ErrorCode.Unknown, "unknown method $methodId")
    }
}
