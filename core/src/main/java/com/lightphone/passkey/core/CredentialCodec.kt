package com.lightphone.passkey.core

import org.json.JSONArray
import org.json.JSONObject

/**
 * The metadata JSON codec (non-secret bookkeeping rows for each resident
 * credential — the private keys live in the Android Keystore, never here).
 * Pure JVM so the round-trip + legacy-row migration are unit-testable.
 *
 * Schema: a JSON array of objects, one per credential. `createdAt` /
 * `lastUsedAt` were added with the manager (2026-08-22); legacy rows without
 * them decode as 0 (unknown / never used) and re-save with the fields set.
 */
object CredentialCodec {

    fun decode(json: String): List<Credential> {
        val arr = JSONArray(json)
        return buildList {
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                add(
                    Credential(
                        credentialId = Base64Url.decode(o.getString("credentialId")),
                        rpId = o.getString("rpId"),
                        userName = o.getString("userName"),
                        userHandle = Base64Url.decode(o.getString("userHandle")),
                        uvBound = o.optBoolean("uvBound", false),
                        signCount = o.getLong("signCount"),
                        createdAt = o.optLong("createdAt", 0),
                        lastUsedAt = o.optLong("lastUsedAt", 0),
                    )
                )
            }
        }
    }

    fun encode(creds: List<Credential>): String {
        val arr = JSONArray()
        for (c in creds) {
            arr.put(
                JSONObject()
                    .put("credentialId", Base64Url.encode(c.credentialId))
                    .put("rpId", c.rpId)
                    .put("userName", c.userName)
                    .put("userHandle", Base64Url.encode(c.userHandle))
                    .put("uvBound", c.uvBound)
                    .put("signCount", c.signCount)
                    .put("createdAt", c.createdAt)
                    .put("lastUsedAt", c.lastUsedAt)
            )
        }
        return arr.toString()
    }
}
