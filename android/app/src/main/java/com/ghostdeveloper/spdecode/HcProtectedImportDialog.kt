package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.parity.HcHccfgPort

/**
 * Only used when HCCFG explicitly declares a password and/or HWID lock.
 * Secure dialog; no key harvesting, device-id autofill or backend interaction.
 * Password input is consumed once and cleared before dismissing the dialog.
 */
@Composable
internal fun HcProtectedImportDialog(
    filename:String,
    requirements:HcHccfgPort.Requirements,
    onSubmit:(password:String?,hwid:String?)->Unit,
    onCancel:()->Unit,
) {
    var password by remember(filename) { mutableStateOf("") }
    var hwid by remember(filename) { mutableStateOf("") }
    val hwidValid=hwid.trim().matches(Regex("[0-9a-fA-FhH]{32}"))
    val ready=(!requirements.passwordRequired || password.isNotEmpty()) &&
        (!requirements.hwidRequired || hwidValid)
    fun dismiss(){
        password=""
        hwid=""
        onCancel()
    }
    AlertDialog(
        onDismissRequest={dismiss()},
        properties=DialogProperties(securePolicy=SecureFlagPolicy.SecureOn),
        title={Text(stringResource(R.string.hc_auth_title))},
        text={
            Column(
                Modifier.fillMaxWidth().verticalScroll(rememberScrollState()),
                verticalArrangement=Arrangement.spacedBy(12.dp),
            ){
                Text(stringResource(R.string.hc_auth_description,filename))
                if(requirements.passwordRequired) {
                    OutlinedTextField(
                        value=password,
                        onValueChange={ if(it.toByteArray(Charsets.UTF_8).size<=4096)password=it },
                        singleLine=true,
                        modifier=Modifier.fillMaxWidth(),
                        label={Text(stringResource(R.string.hc_auth_password))},
                        visualTransformation=PasswordVisualTransformation(),
                        keyboardOptions=KeyboardOptions(
                            capitalization=KeyboardCapitalization.None,
                            autoCorrectEnabled=false),
                    )
                }
                if(requirements.hwidRequired) {
                    OutlinedTextField(
                        value=hwid,
                        onValueChange={if(it.length<=32)hwid=it},
                        singleLine=true,
                        modifier=Modifier.fillMaxWidth(),
                        label={Text(stringResource(R.string.hc_auth_hwid))},
                        supportingText={Text(stringResource(R.string.hc_auth_hwid_hint))},
                        keyboardOptions=KeyboardOptions(
                            capitalization=KeyboardCapitalization.None,
                            autoCorrectEnabled=false),
                    )
                }
                Text(stringResource(R.string.hc_auth_privacy),style=MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton={
            TextButton(enabled=ready,onClick={
                if(ready) {
                    val pw=if(requirements.passwordRequired)password else null
                    val hw=if(requirements.hwidRequired)hwid else null
                    password="";hwid=""
                    onSubmit(pw,hw)
                }
            }){Text(stringResource(R.string.hc_auth_unlock))}
        },
        dismissButton={
            TextButton(onClick={dismiss()}){Text(stringResource(R.string.cancel))}
        }
    )
}
