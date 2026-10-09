package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ContentPaste
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.DataObject
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Separate plain-text input. No rememberSaveable, no file permission and no
 * clipboard reads, so unsubmitted tokens are not persisted or auto-exposed.
 */
@Composable
fun TextDecoderPanel(
    enabled:Boolean,
    onDecode:(String)->Unit,
    onClearSession:()->Unit,
    pendingParts:Int,
    pendingProtocol:String?,
){
    var draft by remember { mutableStateOf("") }
    Surface(shape=RoundedCornerShape(18.dp),color=Color(0xFF242424),
        border=BorderStroke(1.dp,Color(0xFF303030)),
        modifier=Modifier.fillMaxWidth()) {
        Column(
            Modifier.padding(18.dp),
            verticalArrangement=Arrangement.spacedBy(11.dp),
        ) {
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.DataObject,null,
                    tint=Color.White,modifier=Modifier.size(25.dp))
                Spacer(Modifier.width(9.dp))
                Text(stringResource(R.string.text_decode_title),
                    color=Color.White,fontSize=18.sp,fontWeight=FontWeight.Bold)
            }
            Text(stringResource(R.string.text_decode_description),
                fontSize=13.sp,lineHeight=19.sp,color=Color(0xFFBDBDBD))
            OutlinedTextField(
                value=draft,
                onValueChange={if(it.length<=TextProtocolDecoder.MAX_CHARS)draft=it},
                modifier=Modifier.fillMaxWidth(),
                minLines=3,
                maxLines=7,
                label={Text(stringResource(R.string.text_decode_hint))},
                enabled=enabled,
                keyboardOptions=KeyboardOptions(
                    capitalization=KeyboardCapitalization.None,
                    autoCorrectEnabled=false,
                ),
                trailingIcon={
                    if(draft.isNotEmpty()) IconButton(onClick={draft=""}) {
                        Icon(Icons.Outlined.Close,
                            stringResource(R.string.close))
                    }
                },
            )
            if(pendingParts>0) {
                Text(stringResource(R.string.text_decode_pending,
                    pendingProtocol.orEmpty(),pendingParts),
                    color=Color(0xFFF0C77A),fontSize=12.sp,lineHeight=18.sp)
            }
            Row(horizontalArrangement=Arrangement.spacedBy(8.dp),
                verticalAlignment=Alignment.CenterVertically) {
                Button(
                    enabled=enabled&&draft.isNotBlank(),
                    onClick={
                        val text=draft
                        if(text.isNotBlank()) {
                            draft=""
                            onDecode(text)
                        }
                    },
                    colors=ButtonDefaults.buttonColors(
                        containerColor=Color(0xFFF1F1F1),
                        contentColor=Color(0xFF111111)),
                    modifier=Modifier.weight(1f),
                ) {
                    Icon(Icons.Outlined.ContentPaste,null,
                        modifier=Modifier.size(16.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.text_decode_action))
                }
                if(pendingParts>0) OutlinedButton(
                    onClick=onClearSession,
                    enabled=enabled,
                ) {
                    Text(stringResource(R.string.text_decode_reset))
                }
            }
            Text(stringResource(R.string.text_decode_private),
                color=Color(0xFF999999),fontSize=11.sp,lineHeight=16.sp)
        }
    }
}
