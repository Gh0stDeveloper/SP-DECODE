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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.text.DateFormat
import java.util.Date

private val Ink=Color(0xFFF7F7F7)
private val Muted=Color(0xFFABABAB)
private val Edge=Color(0xFF292929)
private val Tile=Color(0xFF242424)

/**
 * JSON is the ONLY on-screen decoded data representation.
 * Decoder raw text is NEVER rewritten. Copy/export continue to support the
 * exact original. The metadata and developer attribution are outside JSON.
 */
@Composable
fun CompleteResultCard(
    current:DecodeView?,
    reveal:Boolean,
    hideCredentials:Boolean,
    onReveal:(Boolean)->Unit,
    onCopy:()->Unit,
    onExport:()->Unit,
) {
    val context=LocalContext.current
    val sample=current==null
    val mask=hideCredentials&&!reveal
    val primary=remember(current?.id,mask) {
        current?.let { ResultJsonDisplay.render(it.rawText,it.extension,mask) }.orEmpty()
    }
    val formattedDate=remember(current?.savedAtMillis,
        context.resources.configuration.locales[0]) {
        current?.let {
            val locale=context.resources.configuration.locales[0]
            DateFormat.getDateTimeInstance(DateFormat.MEDIUM,DateFormat.SHORT,locale)
                .format(Date(it.savedAtMillis))
        }.orEmpty()
    }
    Surface(
        modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(17.dp),
        color=Color.Black,
        border=BorderStroke(1.dp,Edge),
    ) {
        Column(modifier=Modifier.padding(16.dp),
            verticalArrangement=Arrangement.spacedBy(14.dp)) {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.DataObject,null,tint=Muted,
                    modifier=Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(current?.filename ?: stringResource(R.string.example_file),
                    color=Ink,fontSize=14.sp,fontWeight=FontWeight.SemiBold,
                    maxLines=2,overflow=TextOverflow.Ellipsis,
                    modifier=Modifier.weight(1f))
            }
            if(sample) {
                Text(stringResource(R.string.no_result),
                    color=Muted,fontSize=14.sp,lineHeight=20.sp)
                Text(stringResource(R.string.illustrative_warning),
                    color=Muted,fontSize=12.sp)
            } else {
                Column(verticalArrangement=Arrangement.spacedBy(4.dp)) {
                    Text("// "+stringResource(R.string.result_decoded_by,"SP-DECODE"),
                        color=Muted,fontSize=12.sp,lineHeight=17.sp,
                        style=TextStyle(textDirection=TextDirection.Ltr))
                    Text("// "+stringResource(R.string.result_decoded_date,formattedDate),
                        color=Muted,fontSize=12.sp,lineHeight=17.sp,
                        style=TextStyle(textDirection=TextDirection.Ltr))
                    Text("// "+stringResource(R.string.splash_powered_by),
                        color=Muted,fontSize=12.sp,lineHeight=17.sp,
                        style=TextStyle(textDirection=TextDirection.Ltr))
                }
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
            }
            Row(horizontalArrangement=Arrangement.spacedBy(10.dp)) {
                val buttons=ButtonDefaults.buttonColors(
                    containerColor=Tile,contentColor=Ink,
                    disabledContainerColor=Tile,disabledContentColor=Muted)
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
                    shape=RoundedCornerShape(11.dp)) {
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
