package com.lightphone.passkey.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.shared.LightServiceMethod
import com.thelightphone.sdk.ui.LightBarButton
import com.thelightphone.sdk.ui.LightBottomBar
import com.thelightphone.sdk.ui.LightIcons
import com.thelightphone.sdk.ui.LightText
import com.thelightphone.sdk.ui.LightTextVariant
import com.thelightphone.sdk.ui.LightTheme
import com.thelightphone.sdk.ui.LightThemeController
import com.thelightphone.sdk.ui.LightThemeTokens
import com.thelightphone.sdk.ui.LightTopBar
import com.thelightphone.sdk.ui.LightTopBarCenter
import com.thelightphone.sdk.ui.gridUnitsAsDp
import java.text.DateFormat
import java.util.Date

/**
 * One passkey's detail panel — opened by tapping a row in the list. The top
 * bar carries the account name; the body shows the site (RP domain), when it
 * was created, and when it was last used. The bottom bar's REMOVE opens the
 * delete-confirm panel (a confirmed delete pops this panel with `true`).
 */
class PasskeysDetailsViewModel : LightViewModel<Boolean>()

class PasskeysDetailsScreen(
    sealedActivity: SealedLightActivity,
    private val credential: LightServiceMethod.CredentialInfo,
) : LightScreen<Boolean, PasskeysDetailsViewModel>(sealedActivity) {

    override val viewModelClass: Class<PasskeysDetailsViewModel> = PasskeysDetailsViewModel::class.java

    override fun createViewModel(): PasskeysDetailsViewModel = PasskeysDetailsViewModel()

    @Composable
    override fun Content() {
        val themeColors by LightThemeController.colors.collectAsState()

        LightTheme(colors = themeColors) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(LightThemeTokens.colors.background)
            ) {
                LightTopBar(
                    leftButton = LightBarButton.LightIcon(
                        icon = LightIcons.BACK,
                        onClick = { goBack() },
                        contentDescription = "Back to Passkeys",
                    ),
                    center = LightTopBarCenter.Text(text = credential.userName),
                )

                // Generous buffer under the top bar; white-only text (name,
                // site in brackets, dates) — hierarchy from size, not color.
                Column(
                    modifier = Modifier
                        .padding(top = 3f.gridUnitsAsDp())
                        .padding(horizontal = 2f.gridUnitsAsDp())
                ) {
                    LightText(
                        text = credential.userName,
                        variant = LightTextVariant.Copy,
                        modifier = Modifier.padding(bottom = 0.4f.gridUnitsAsDp()),
                    )
                    LightText(
                        text = "(${credential.rpId})",
                        variant = LightTextVariant.Fine,
                        modifier = Modifier.padding(bottom = 1f.gridUnitsAsDp()),
                    )
                    date(credential.createdAt)?.let {
                        LightText(
                            text = "Created $it",
                            variant = LightTextVariant.Fine,
                            modifier = Modifier.padding(bottom = 0.2f.gridUnitsAsDp()),
                        )
                    }
                    date(credential.lastUsedAt)?.let {
                        LightText(
                            text = "Last used $it",
                            variant = LightTextVariant.Fine,
                            modifier = Modifier.padding(bottom = 0.2f.gridUnitsAsDp()),
                        )
                    }
                }

                Spacer(Modifier.weight(1f))

                // Bottom bar: a single centered action — REMOVE (the primary
                // command) opens the delete confirmation.
                LightBottomBar(
                    modifier = Modifier.navigationBarsPadding(),
                    items = listOf(
                        LightBarButton.Text(
                            text = "REMOVE",
                            onClick = {
                                navigateTo(screenFactory = { DeleteCredentialScreen(it, credential) }) { deleted ->
                                    if (deleted == true) goBack(true)
                                }
                            },
                        ),
                    ),
                )
            }
        }
    }
}

/** Locale-aware date only ("Aug 22, 2026"); null when 0 (legacy/never). */
private fun date(epochMillis: Long): String? =
    if (epochMillis > 0) DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(epochMillis)) else null
