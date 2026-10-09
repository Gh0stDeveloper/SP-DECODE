package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.text.style.TextAlign

private val Ink=Color(0xFFF6F6F6)
private val Muted=Color(0xFFADADAD)
private val Edge=Color(0xFF292929)
private val Tile=Color(0xFF242424)

/** All source fields, including deeply nested JSON, with no arbitrary item cap
 * or 3-line ellipsis. Only actual password credential fields may be masked by
 * an explicitly enabled preference. Raw source remains immutable in memory.
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
    var rawExpanded by remember(current){mutableStateOf(false)}
    val sample=current==null
    val fields=current?.document?.fields.orEmpty()
    val name=current?.filename ?: stringResource(R.string.example_file)
    val suffix=current?.extension ?: "tls"
    Surface(
        modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(17.dp),
        color=Color.Black,
        border=BorderStroke(1.dp,Edge),
    ){
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(15.dp)){
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.CheckCircle,null,
                    tint=if(sample)Color(0xFF40A06D) else Color(0xFFE0B563),
                    modifier=Modifier.size(21.dp))
                Spacer(Modifier.width(9.dp))
                Text(name,color=Ink,fontWeight=FontWeight.SemiBold,fontSize=17.sp,
                    maxLines=2,overflow=TextOverflow.Ellipsis,modifier=Modifier.weight(1f))
                Spacer(Modifier.width(7.dp))
                Surface(color=if(sample)Color(0xFF102A1C)else Color(0xFF332715),
                    shape=RoundedCornerShape(50.dp)){
                    Text(stringResource(if(sample)R.string.sample else R.string.experimental),
                        color=if(sample)Color(0xFF62C898)else Color(0xFFE0B563),
                        fontSize=12.sp,modifier=Modifier.padding(horizontal=10.dp,vertical=5.dp))
                }
            }
            HorizontalDivider(color=Edge)
            Column(verticalArrangement=Arrangement.spacedBy(4.dp)){
                Text(stringResource(R.string.format),color=Muted,fontSize=12.sp)
                Text(suffix.uppercase(),color=Ink,fontSize=15.sp)
            }
            if(sample) {
                FullField(stringResource(R.string.server),"example.com",false,false,onReveal)
                FullField(stringResource(R.string.port),"443",false,false,onReveal)
                FullField(stringResource(R.string.password),"••••••••",false,false,onReveal)
                Text(stringResource(R.string.illustrative_warning),color=Muted,fontSize=11.sp)
            }else if(fields.isEmpty()){
                // Never hide unrecognized original output formats.
                SelectionContainer {
                    Text(current!!.rawText,color=Ink,fontSize=13.sp,lineHeight=19.sp,
                        style=TextStyle(textDirection=TextDirection.Ltr))
                }
            }else{
                Text(stringResource(R.string.complete_fields_count,fields.size),
                    color=Muted,fontSize=12.sp)
                // Do not use take(10), maxLines or ellipsize: this is the user's
                // main requirement. The page itself scrolls naturally.
                fields.forEach {field->
                    key(field.path){
                        FullField(field.path,field.value,
                            hideCredentials&&field.confidential,
                            reveal,onReveal)
                        HorizontalDivider(color=Edge.copy(alpha=0.55f),
                            thickness=0.5.dp)
                    }
                }
            }
            if(!sample) {
                TextButton(
                    onClick={rawExpanded=!rawExpanded},
                    contentPadding=PaddingValues(0.dp),
                ){
                    Text(stringResource(R.string.raw_text),color=Muted,fontSize=13.sp)
                    Spacer(Modifier.width(8.dp))
                    Icon(if(rawExpanded)Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                        null,tint=Muted,modifier=Modifier.size(18.dp))
                }
                if(rawExpanded){
                    SelectionContainer{
                        Text(
                            if(hideCredentials&&!reveal)current!!.redactedText
                                else current!!.rawText,
                            color=Ink,fontSize=12.sp,lineHeight=18.sp,
                            style=TextStyle(textDirection=TextDirection.Ltr)
                        )
                    }
                }
            }
            Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){
                Button(onClick=onCopy,enabled=!sample,
                    modifier=Modifier.weight(1f),
                    colors=ButtonDefaults.buttonColors(containerColor=Tile),
                    shape=RoundedCornerShape(11.dp)){
                    Icon(Icons.Outlined.ContentCopy,null,modifier=Modifier.size(17.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.copy),fontSize=13.sp)
                }
                Button(onClick=onExport,enabled=!sample,
                    modifier=Modifier.weight(1f),
                    colors=ButtonDefaults.buttonColors(containerColor=Tile),
                    shape=RoundedCornerShape(11.dp)){
                    Icon(Icons.Outlined.FileDownload,null,modifier=Modifier.size(17.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.export),fontSize=13.sp)
                }
            }
        }
    }
}

@Composable
private fun FullField(label:String,value:String,sensitive:Boolean,reveal:Boolean,
                      onReveal:(Boolean)->Unit){
    Column(Modifier.fillMaxWidth(),verticalArrangement=Arrangement.spacedBy(6.dp)){
        Row(verticalAlignment=Alignment.CenterVertically){
            Text(label,color=Muted,fontSize=12.sp,lineHeight=17.sp,
                modifier=Modifier.weight(1f))
            if(sensitive){
                IconButton(onClick={onReveal(!reveal)},modifier=Modifier.size(32.dp)){
                    Icon(if(reveal)Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                        stringResource(if(reveal)R.string.hide else R.string.show),
                        tint=Muted,modifier=Modifier.size(18.dp))
                }
            }
        }
        SelectionContainer{
            Text(if(sensitive&&!reveal)"••••••••" else value,
                color=Ink,fontSize=14.sp,lineHeight=20.sp,
                style=TextStyle(textDirection=TextDirection.Ltr),
                modifier=Modifier.fillMaxWidth())
        }
    }
}
