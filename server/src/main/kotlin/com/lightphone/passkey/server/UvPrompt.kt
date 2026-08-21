package com.lightphone.passkey.server

import android.content.Context
import android.content.Intent
import androidx.biometric.BiometricPrompt
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CompletableDeferred

/**
 * Bridge between the session's suspended UV gate and the [UvActivity]
 * FragmentActivity that hosts the BiometricPrompt (the tool runtime forbids
 * BiometricPrompt — UV runs in the merged server module). [prompt] launches
 * the activity and suspends until it reports the result; the CryptoObject
 * (which authorizes a UV-bound Keystore key) is handed over in-process since
 * it isn't Parcelable.
 */
object UvPrompt {

    const val EXTRA_ID = "uv_id"
    const val EXTRA_TITLE = "uv_title"
    const val EXTRA_SUBTITLE = "uv_subtitle"

    private val pending = ConcurrentHashMap<Long, CompletableDeferred<Boolean>>()
    // Only present when a CryptoObject rides along (a UV-bound key's GA);
    // registration has none. ConcurrentHashMap rejects null values.
    private val cryptos = ConcurrentHashMap<Long, BiometricPrompt.CryptoObject>()
    private val nextId = AtomicLong(0)

    suspend fun prompt(
        context: Context,
        title: String,
        subtitle: String,
        crypto: BiometricPrompt.CryptoObject?,
    ): Boolean {
        val id = nextId.incrementAndGet()
        val result = CompletableDeferred<Boolean>()
        pending[id] = result
        if (crypto != null) cryptos[id] = crypto
        context.startActivity(
            Intent(context, UvActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                .putExtra(EXTRA_ID, id)
                .putExtra(EXTRA_TITLE, title)
                .putExtra(EXTRA_SUBTITLE, subtitle),
        )
        return result.await()
    }

    fun crypto(id: Long): BiometricPrompt.CryptoObject? = cryptos[id]

    fun complete(id: Long, ok: Boolean) {
        pending.remove(id)?.complete(ok)
        cryptos.remove(id)
    }
}
