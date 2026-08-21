package com.lightphone.passkey.server

import android.os.Bundle
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.lightphone.passkey.core.UvGate
import kotlinx.coroutines.launch

/**
 * Hosts the BiometricPrompt for a pending UV (launched by [UvPrompt] while the
 * session's responder is suspended): prompts, reports the result back to the
 * waiting coroutine, and finishes. FragmentActivity so the prompt has a
 * FragmentManager; transparent theme so it reads as a system prompt.
 */
class UvActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val id = intent.getLongExtra(UvPrompt.EXTRA_ID, 0L)
        val title = intent.getStringExtra(UvPrompt.EXTRA_TITLE) ?: "Passkey"
        val subtitle = intent.getStringExtra(UvPrompt.EXTRA_SUBTITLE) ?: ""
        lifecycleScope.launch {
            val ok = UvGate.authenticate(this@UvActivity, title, subtitle, UvPrompt.crypto(id))
            UvPrompt.complete(id, ok)
            finish()
        }
    }
}
