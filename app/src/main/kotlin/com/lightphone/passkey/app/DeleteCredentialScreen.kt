package com.lightphone.passkey.app

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.lifecycle.viewModelScope
import com.thelightphone.sdk.LightScreen
import com.thelightphone.sdk.LightViewModel
import com.thelightphone.sdk.SealedLightActivity
import com.thelightphone.sdk.SimpleLightScreen
import com.thelightphone.sdk.callRemoteServiceMethod
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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * The delete-confirm panel — opened by tapping a passkey in the list. Asks
 * before deleting the passkey's Keystore key + metadata row.
 *
 * Result: `true` after a confirmed delete (the list reloads), nothing when
 * dismissed.
 */
class DeleteCredentialViewModel(private val credential: LightServiceMethod.CredentialInfo) :
    LightViewModel<Boolean>() {

    // Guards against double-taps while the delete call is in flight.
    private val busy = MutableStateFlow(false)

    fun delete(screen: SimpleLightScreen<Boolean>) {
        if (busy.value) return
        viewModelScope.launch {
            busy.value = true
            callRemoteServiceMethod(
                LightServiceMethod.DeletePasskey,
                LightServiceMethod.DeletePasskey.Request(credential.credentialId),
            )
            busy.value = false
            screen.goBack(true)
        }
    }
}

class DeleteCredentialScreen(
    sealedActivity: SealedLightActivity,
    private val credential: LightServiceMethod.CredentialInfo,
) : LightScreen<Boolean, DeleteCredentialViewModel>(sealedActivity) {

    override val viewModelClass: Class<DeleteCredentialViewModel> = DeleteCredentialViewModel::class.java

    override fun createViewModel(): DeleteCredentialViewModel = DeleteCredentialViewModel(credential)

    @Composable
    override fun Content() {
        val themeColors by LightThemeController.colors.collectAsState()

        LightTheme(colors = themeColors) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .background(LightThemeTokens.colors.background),
            ) {
                LightTopBar(
                    leftButton = LightBarButton.LightIcon(
                        icon = LightIcons.BACK,
                        onClick = { goBack() },
                        contentDescription = "Back to Passkeys",
                    ),
                    center = LightTopBarCenter.Text(text = "Delete Passkey"),
                )
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    LightText(
                        text = "Delete the passkey for ${credential.userName} on ${credential.rpId}?",
                        variant = LightTextVariant.Copy,
                        align = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 3f.gridUnitsAsDp()),
                    )
                }
                LightBottomBar(
                    modifier = Modifier.navigationBarsPadding(),
                    items = listOf(
                        LightBarButton.Text(
                            text = "DELETE",
                            onClick = { viewModel.delete(this@DeleteCredentialScreen) },
                        ),
                        null,
                        LightBarButton.Text(
                            text = "CANCEL",
                            onClick = { goBack() },
                        ),
                    ),
                )
            }
        }
    }
}
