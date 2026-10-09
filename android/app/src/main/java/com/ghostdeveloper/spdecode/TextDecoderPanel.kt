package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.DataObject
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Expanded-only offline text editor. Input stays in Compose memory and is
 * discarded when this panel closes. It is never saved before decoding succeeds.
 * Full links are submitted in one operation, without Telegram-style parts.
 */
@Composable
fun TextDecoderPanel(
    enabled:Boolean,
    onDecode:(String)->Unit,
) {
    var draft by remember { mutableStateOf("") }
    Surface(
        modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(15.dp),
        color=Color(0xFF242424),
        border=BorderStroke(1.dp,Color(0xFF303030)),
    ) {
        Column(
            modifier=Modifier.padding(12.dp),
            verticalArrangement=Arrangement.spacedBy(9.dp),
        ) {
            OutlinedTextField(
                value=draft,
                onValueChange={if(it.length<=TextProtocolDecoder.MAX_CHARS)draft=it},
                modifier=Modifier.fillMaxWidth(),
                minLines=3,
                maxLines=6,
                placeholder={Text(stringResource(R.string.text_decode_hint))},
                enabled=enabled,
                keyboardOptions=KeyboardOptions(
                    capitalization=KeyboardCapitalization.None,
                    autoCorrectEnabled=false,
                ),
                trailingIcon={
                    if(draft.isNotEmpty()) IconButton(
                        onClick={draft=""},
                        enabled=enabled,
                    ) {
                        Icon(Icons.Outlined.Close,
                            stringResource(R.string.close))
                    }
                },
            )
            Button(
                enabled=enabled && draft.isNotBlank(),
                onClick={
                    if(draft.isNotBlank()) onDecode(draft)
                },
                modifier=Modifier.fillMaxWidth().heightIn(min=44.dp),
                shape=RoundedCornerShape(12.dp),
                colors=ButtonDefaults.buttonColors(
                    containerColor=Color(0xFFF1F1F1),
                    contentColor=Color(0xFF111111)),
            ) {
                Icon(Icons.Outlined.DataObject,null,modifier=Modifier.size(17.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.text_decode_action),fontSize=14.sp)
            }
            Text(
                stringResource(R.string.text_decode_private),
                fontSize=11.sp,lineHeight=16.sp,color=Color(0xFF999999),
            )
        }
    }
}
