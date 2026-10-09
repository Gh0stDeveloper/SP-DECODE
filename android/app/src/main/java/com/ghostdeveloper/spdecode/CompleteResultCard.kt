package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Ink=Color(0xFFF7F7F7)
private val Muted=Color(0xFFABABAB)
private val Edge=Color(0xFF292929)
private val Tile=Color(0xFF242424)

/**
 * The screenshot-approved original bot-style output is PRIMARY. No flattening,
 * cap, loss of nested fields, reordering, or accidental JSON-to-text export.
 * Organized nested JSON is a DISPLAY view; the raw text is immutable.
 */
@Composable
fun CompleteResultCard(
    current:DecodeView?,
    reveal:Boolean,
    hideCredentials:Boolean,
    onReveal:(Boolean)->Unit,
    onCopy:()->Unit,
    onExport:()->Unit,
){
    var rawExpanded by remember(current?.id){mutableStateOf(false)}
    var fieldsExpanded by remember(current?.id){mutableStateOf(false)}
    val sample=current==null
    val fields=current?.document?.fields.orEmpty()
    val mask=hideCredentials&&!reveal
    // Cache formatting by the immutable raw input and active privacy mode.
    val primary=remember(current?.id,mask) {
        current?.let { RawResultFormatter.render(it.rawText,mask) }.orEmpty()
    }
    Surface(
        modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(17.dp),
        color=Color.Black,
        border=BorderStroke(1.dp,Edge),
    ){
        Column(
            modifier=Modifier.padding(16.dp),
            verticalArrangement=Arrangement.spacedBy(14.dp),
        ){
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Description,null,tint=Muted,
                    modifier=Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(current?.filename ?: stringResource(R.string.example_file),
                    color=Ink,fontSize=14.sp,fontWeight=FontWeight.SemiBold,
                    maxLines=2,overflow=TextOverflow.Ellipsis,
                    modifier=Modifier.weight(1f))
                if(!sample) {
                    Spacer(Modifier.width(5.dp))
                    Text(stringResource(R.string.experimental),
                        color=Muted,fontSize=11.sp)
                }
            }
            HorizontalDivider(color=Edge)
            if(sample) {
                Text(stringResource(R.string.no_result),
                    color=Muted,fontSize=14.sp,lineHeight=20.sp)
                Text(stringResource(R.string.illustrative_warning),
                    color=Muted,fontSize=12.sp)
            }else{
                // Full decoder appearance, with JSON objects expanded *inside*
                // the original key/value blocks. User text remains selectable.
                SelectionContainer {
                    Text(primary,color=Ink,fontSize=13.sp,lineHeight=19.sp,
                        style=TextStyle(textDirection=TextDirection.Ltr),
                        modifier=Modifier.fillMaxWidth())
                }
                if(hideCredentials) {
                    TextButton(onClick={onReveal(!reveal)},
                        contentPadding=PaddingValues(0.dp)) {
                        Icon(if(reveal)Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                            null,tint=Ink,modifier=Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(if(reveal)R.string.hide else R.string.show),
                            color=Ink)
                    }
                }
                Row(verticalAlignment=Alignment.CenterVertically,
                    horizontalArrangement=Arrangement.spacedBy(12.dp)) {
                    TextButton(onClick={rawExpanded=!rawExpanded},
                        contentPadding=PaddingValues(0.dp)) {
                        Text(stringResource(R.string.raw_text),color=Ink,fontSize=12.sp)
                        Spacer(Modifier.width(4.dp))
                        Icon(if(rawExpanded)Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                            null,tint=Ink,modifier=Modifier.size(18.dp))
                    }
                    if(fields.isNotEmpty()) TextButton(
                        onClick={fieldsExpanded=!fieldsExpanded},
                        contentPadding=PaddingValues(0.dp)) {
                        Text(stringResource(R.string.detailed_fields),color=Muted,fontSize=12.sp)
                        Icon(if(fieldsExpanded)Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                            null,tint=Muted,modifier=Modifier.size(18.dp))
                    }
                }
                if(rawExpanded) {
                    if(mask) Text(stringResource(R.string.raw_masked_explanation),
                        color=Muted,fontSize=12.sp,lineHeight=18.sp)
                    else SelectionContainer {
                        Text(current.rawText,color=Ink,fontSize=12.sp,lineHeight=18.sp,
                            style=TextStyle(textDirection=TextDirection.Ltr))
                    }
                }
                if(fieldsExpanded) {
                    Text(stringResource(R.string.complete_fields_count,fields.size),
                        color=Muted,fontSize=12.sp)
                    fields.forEach { field ->
                        Column(verticalArrangement=Arrangement.spacedBy(3.dp)) {
                            Text(field.path,color=Muted,fontSize=12.sp,
                                style=TextStyle(textDirection=TextDirection.Ltr))
                            SelectionContainer {
                                Text(if(mask&&field.confidential)"••••••••" else field.value,
                                    color=Ink,fontSize=13.sp,lineHeight=19.sp,
                                    style=TextStyle(textDirection=TextDirection.Ltr))
                            }
                        }
                        HorizontalDivider(color=Edge)
                    }
                }
            }
            Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){
                val buttons=ButtonDefaults.buttonColors(
                    containerColor=Tile,contentColor=Ink,
                    disabledContainerColor=Tile,disabledContentColor=Muted,
                )
                Button(onClick=onCopy,enabled=!sample,
                    modifier=Modifier.weight(1f),colors=buttons,
                    shape=RoundedCornerShape(11.dp)) {
                    Icon(Icons.Outlined.ContentCopy,null,tint=if(sample)Muted else Ink,
                        modifier=Modifier.size(17.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.copy),color=if(sample)Muted else Ink,
                        fontSize=13.sp)
                }
                Button(onClick=onExport,enabled=!sample,
                    modifier=Modifier.weight(1f),colors=buttons,
                    shape=RoundedCornerShape(11.dp)){
                    Icon(Icons.Outlined.FileDownload,null,tint=if(sample)Muted else Ink,
                        modifier=Modifier.size(17.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.export),color=if(sample)Muted else Ink,
                        fontSize=13.sp)
                }
            }
        }
    }
}
