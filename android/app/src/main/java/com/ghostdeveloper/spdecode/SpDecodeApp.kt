package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog

/** Authoritative reference is the USER-PROVIDED 2026-10-08 ChatGPT capture:
 * true black, #242424 centered import hero, thin result border and white text,
 * four monochrome bottom tabs, compact title with rounded shield icon.
 * This replaces mismatched older SVG illustrations for the functional UI.
 */
private val Background=Color(0xFF000000)
private val Panel=Color(0xFF242424)
private val Raised=Color(0xFF2A2A2A)
private val Outline=Color(0xFF202020)
private val White=Color(0xFFF7F7F7)
private val Secondary=Color(0xFFABABAB)
private val Green=Color(0xFF38A36D)
private val Amber=Color(0xFFE0B563)

@Composable
fun SpDecodeApp(
    activeTab:Int,
    current:DecodeView?,
    session:List<DecodeView>,
    busy:Boolean,
    error:String?,
    reveal:Boolean,
    onTab:(Int)->Unit,
    onImport:()->Unit,
    onImportMultiple:()->Unit,
    onCancel:()->Unit,
    onReveal:(Boolean)->Unit,
    onCopy:(Boolean)->Unit,
    onExport:(Boolean)->Unit,
    onSelect:(DecodeView)->Unit,
    onClear:()->Unit,
    onDismissError:()->Unit
){
    var dialog by remember{mutableStateOf<String?>(null)}
    MaterialTheme(colorScheme=darkColorScheme(
        primary=White,
        onPrimary=Background,
        background=Background,
        surface=Background,
        onSurface=White,
        onBackground=White,
        outline=Outline,
    )){
        Column(
            modifier=Modifier.fillMaxSize().background(Background).safeDrawingPadding()
        ) {
            BrandHeader(onSettings={onTab(3)})
            Box(Modifier.weight(1f)) {
                when(activeTab) {
                    0->HomeScreen(current,session,busy,reveal,onImport,onCancel,onReveal,
                        onCopy={dialog="copy"},onExport={dialog="export"},onSelect=onSelect)
                    1->HistoryScreen(session,onSelect,onClear,onImportMultiple)
                    2->FormatsScreen()
                    else->SettingsScreen(onClear)
                }
            }
            BottomTabs(activeTab,onTab)
        }
        if(error!=null)AlertDialog(
            onDismissRequest=onDismissError,
            title={Text(stringResource(R.string.import_error))},
            text={Text(error)},
            confirmButton={TextButton(onClick=onDismissError){
                Text(stringResource(R.string.close))
            }},
            containerColor=Panel,
            titleContentColor=White,
            textContentColor=Secondary,
        )
        if(dialog!=null && current!=null) {
            val copy=dialog=="copy"
            AlertDialog(
                onDismissRequest={dialog=null},
                title={Text(stringResource(if(copy)R.string.copy_question else R.string.export_question))},
                text={
                    Column(verticalArrangement=Arrangement.spacedBy(14.dp)) {
                        Text(stringResource(R.string.privacy_warning),color=Secondary,fontSize=14.sp)
                        TextButton(
                            modifier=Modifier.fillMaxWidth(),
                            onClick={
                                if(copy)onCopy(false)else onExport(false)
                                dialog=null
                            }
                        ){
                            Icon(if(copy)Icons.Outlined.ContentCopy else Icons.Outlined.FileDownload,null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(if(copy)R.string.masked_copy else R.string.masked_export))
                        }
                        OutlinedButton(
                            modifier=Modifier.fillMaxWidth(),
                            onClick={
                                if(copy)onCopy(true)else onExport(true)
                                dialog=null
                            }
                        ){
                            Icon(Icons.Outlined.Visibility,null)
                            Spacer(Modifier.width(8.dp))
                            Text(stringResource(if(copy)R.string.full_copy else R.string.full_export))
                        }
                    }
                },
                confirmButton={TextButton(onClick={dialog=null}){Text(stringResource(R.string.cancel))}},
                containerColor=Panel,titleContentColor=White,textContentColor=White,
            )
        }
    }
}

@Composable
private fun BrandHeader(onSettings:()->Unit){
    Row(
        modifier=Modifier.fillMaxWidth().padding(start=20.dp,end=12.dp,top=14.dp,bottom=11.dp),
        verticalAlignment=Alignment.CenterVertically,
    ){
        Box(
            Modifier.size(45.dp).background(Panel,RoundedCornerShape(13.dp)),
            contentAlignment=Alignment.Center,
        ){
            Icon(Icons.Outlined.Shield,null,tint=White,modifier=Modifier.size(26.dp))
        }
        Spacer(Modifier.width(11.dp))
        Column(Modifier.weight(1f)){
            Text("SP-DECODE",color=White,fontSize=23.sp,fontWeight=FontWeight.Bold,
                maxLines=1)
            Text(stringResource(R.string.subtitle),color=Secondary,fontSize=14.sp,
                maxLines=1,overflow=TextOverflow.Ellipsis)
        }
        IconButton(onClick=onSettings){
            Icon(Icons.Outlined.Tune,stringResource(R.string.settings),tint=Secondary)
        }
    }
}

@Composable
private fun HomeScreen(
    current:DecodeView?,
    session:List<DecodeView>,
    busy:Boolean,
    reveal:Boolean,
    onImport:()->Unit,
    onCancel:()->Unit,
    onReveal:(Boolean)->Unit,
    onCopy:()->Unit,
    onExport:()->Unit,
    onSelect:(DecodeView)->Unit
) {
    Column(
        modifier=Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=11.dp),
        verticalArrangement=Arrangement.spacedBy(19.dp),
    ) {
        Surface(shape=RoundedCornerShape(18.dp),color=Panel,modifier=Modifier.fillMaxWidth()){
            Column(
                modifier=Modifier.fillMaxWidth().padding(horizontal=22.dp,vertical=25.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
            ){
                Icon(Icons.Outlined.FileUpload,null,tint=White,modifier=Modifier.size(34.dp))
                Spacer(Modifier.height(16.dp))
                Text(stringResource(R.string.import_title),color=White,
                    fontSize=19.sp,fontWeight=FontWeight.Bold,textAlign=TextAlign.Center)
                Spacer(Modifier.height(12.dp))
                Text(stringResource(R.string.import_detail),color=Secondary,
                    fontSize=15.sp,lineHeight=23.sp,textAlign=TextAlign.Center)
                Spacer(Modifier.height(12.dp))
                if(busy) {
                    CircularProgressIndicator(color=White,modifier=Modifier.size(24.dp),
                        strokeWidth=2.dp)
                    Spacer(Modifier.height(8.dp))
                    Text(stringResource(R.string.file_processing),color=Secondary,fontSize=13.sp)
                    TextButton(onClick=onCancel){Text(stringResource(R.string.processing_cancel))}
                }else{
                    Button(
                        onClick=onImport,
                        shape=RoundedCornerShape(40.dp),
                        colors=ButtonDefaults.buttonColors(containerColor=Raised,contentColor=White),
                        contentPadding=PaddingValues(horizontal=18.dp,vertical=9.dp),
                    ){Text(stringResource(R.string.select_file),fontSize=15.sp,
                        fontWeight=FontWeight.SemiBold)}
                }
            }
        }

        Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){
            Text(stringResource(R.string.result),color=White,fontWeight=FontWeight.Bold,
                fontSize=18.sp,modifier=Modifier.weight(1f))
            Text(
                if(current==null)stringResource(R.string.illustrative)
                else stringResource(R.string.experimental),
                color=Secondary,fontSize=12.sp
            )
        }
        ResultCard(current,reveal,onReveal,onCopy,onExport)
        Row(verticalAlignment=Alignment.CenterVertically){
            Icon(Icons.Outlined.Lock,null,tint=Secondary,modifier=Modifier.size(15.dp))
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.offline_status),fontSize=12.sp,color=Secondary)
        }
        if(session.size>1){
            Text(stringResource(R.string.recent),fontWeight=FontWeight.SemiBold,color=White)
            session.drop(1).take(3).forEach{item->
                Row(
                    modifier=Modifier.fillMaxWidth().clickable{onSelect(item)}
                        .padding(vertical=8.dp),
                    verticalAlignment=Alignment.CenterVertically,
                ){
                    Icon(Icons.Outlined.InsertDriveFile,null,tint=Secondary)
                    Spacer(Modifier.width(10.dp))
                    Text(item.filename,color=White,modifier=Modifier.weight(1f),
                        maxLines=1,overflow=TextOverflow.Ellipsis)
                    Icon(Icons.Outlined.KeyboardArrowRight,null,tint=Secondary)
                }
            }
        }
    }
}

@Composable
private fun ResultCard(
    current:DecodeView?,
    reveal:Boolean,
    onReveal:(Boolean)->Unit,
    onCopy:()->Unit,
    onExport:()->Unit,
){
    var rawExpanded by remember(current){mutableStateOf(false)}
    val example=current==null
    val file=current?.filename?:stringResource(R.string.example_file)
    val suffix=current?.extension?:"tls"
    val fields=if(example)listOf(
        stringResource(R.string.server) to "example.com",
        stringResource(R.string.port) to "443",
        stringResource(R.string.password) to "••••••••"
    )else current!!.fields.filterNot{(k,_)->
        k.contains("𝗚𝗥𝗢𝗨𝗣")||k.contains("𝗖𝗛𝗔𝗡𝗡𝗘𝗟")
    }.take(10)
    Surface(
        shape=RoundedCornerShape(16.dp),
        color=Background,
        border=BorderStroke(1.dp,Outline),
        modifier=Modifier.fillMaxWidth()
    ){
        Column(Modifier.padding(15.dp),verticalArrangement=Arrangement.spacedBy(15.dp)) {
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.CheckCircle,null,tint=if(example)Green else Amber,
                    modifier=Modifier.size(20.dp))
                Spacer(Modifier.width(10.dp))
                Text(file,color=White,fontSize=16.sp,fontWeight=FontWeight.Bold,
                    maxLines=1,overflow=TextOverflow.Ellipsis,modifier=Modifier.weight(1f))
                Spacer(Modifier.width(6.dp))
                Surface(color=if(example)Color(0xFF082216)else Color(0xFF302615),
                    shape=RoundedCornerShape(18.dp)){
                    Text(stringResource(if(example)R.string.sample else R.string.experimental),
                        modifier=Modifier.padding(horizontal=9.dp,vertical=5.dp),
                        color=if(example)Green else Amber,fontSize=11.sp,
                        fontWeight=FontWeight.SemiBold)
                }
            }
            HorizontalDivider(color=Outline,thickness=1.dp)
            FieldRow(stringResource(R.string.format),
                if(suffix=="tls")"TLS Tunnel" else suffix.uppercase(),false,reveal,onReveal)
            fields.forEach{(name,value)->
                FieldRow(name,value, !example && RedactionPolicy.isSensitive(name),
                    reveal,onReveal)
            }
            if(example)Text(stringResource(R.string.illustrative_warning),
                fontSize=11.sp,color=Secondary)
            if(!example){
                HorizontalDivider(color=Outline)
                TextButton(onClick={rawExpanded=!rawExpanded},contentPadding=PaddingValues(0.dp)){
                    Text(stringResource(R.string.raw_text),color=Secondary,fontSize=13.sp)
                    Spacer(Modifier.width(8.dp))
                    Icon(if(rawExpanded)Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                        null,tint=Secondary,modifier=Modifier.size(18.dp))
                }
                if(rawExpanded){
                    SelectionContainer {
                        Text(
                            if(reveal)current!!.rawText else current!!.redactedText,
                            color=White,fontSize=12.sp,lineHeight=18.sp,
                            style=TextStyle(textDirection=TextDirection.Ltr)
                        )
                    }
                }
            }
            Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){
                ActionButton(stringResource(R.string.copy),Icons.Outlined.ContentCopy,
                    enabled=!example,onClick=onCopy,modifier=Modifier.weight(1f))
                ActionButton(stringResource(R.string.export),Icons.Outlined.FileDownload,
                    enabled=!example,onClick=onExport,modifier=Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun FieldRow(name:String,value:String,sensitive:Boolean,reveal:Boolean,
                     onReveal:(Boolean)->Unit) {
    Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){
        Text(name,color=Secondary,fontSize=13.sp,maxLines=2,modifier=Modifier.weight(0.43f))
        Row(
            modifier=Modifier.weight(0.57f),
            horizontalArrangement=Arrangement.End,
            verticalAlignment=Alignment.CenterVertically,
        ){
            Text(if(sensitive&&!reveal)"••••••••" else value,
                color=White,fontSize=13.sp,maxLines=3,
                overflow=TextOverflow.Ellipsis,textAlign=TextAlign.End,
                style=TextStyle(textDirection=TextDirection.Ltr),
                modifier=Modifier.weight(1f,fill=false))
            if(sensitive){
                IconButton(onClick={onReveal(!reveal)},modifier=Modifier.size(29.dp)){
                    Icon(if(reveal)Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                        stringResource(if(reveal)R.string.hide else R.string.show),
                        tint=Secondary,modifier=Modifier.size(19.dp))
                }
            }
        }
    }
}
@Composable
private fun ActionButton(
    title:String,
    icon:androidx.compose.ui.graphics.vector.ImageVector,
    enabled:Boolean,
    onClick:()->Unit,
    modifier:Modifier=Modifier
){
    Button(onClick=onClick,enabled=enabled,modifier=modifier.heightIn(min=47.dp),
        colors=ButtonDefaults.buttonColors(containerColor=Panel,contentColor=White,
            disabledContainerColor=Panel,disabledContentColor=Secondary),
        shape=RoundedCornerShape(11.dp),contentPadding=PaddingValues(horizontal=8.dp)){
        Icon(icon,null,modifier=Modifier.size(17.dp))
        Spacer(Modifier.width(7.dp))
        Text(title,fontSize=13.sp,fontWeight=FontWeight.SemiBold)
    }
}

@Composable
private fun HistoryScreen(session:List<DecodeView>,onSelect:(DecodeView)->Unit,
                          onClear:()->Unit,onImportMultiple:()->Unit) {
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())
        .padding(20.dp),verticalArrangement=Arrangement.spacedBy(16.dp)) {
        Text(stringResource(R.string.history),fontSize=24.sp,fontWeight=FontWeight.Bold)
        Text(stringResource(R.string.session_only),color=Secondary,fontSize=13.sp)
        if(session.isEmpty()){
            CardText(stringResource(R.string.empty_history))
        }else{
            session.forEach{item->
                Surface(
                    color=Panel,shape=RoundedCornerShape(14.dp),
                    modifier=Modifier.fillMaxWidth().clickable {onSelect(item)}
                ){
                    Row(Modifier.padding(16.dp),verticalAlignment=Alignment.CenterVertically){
                        Icon(Icons.Outlined.InsertDriveFile,null,tint=White)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)){
                            Text(item.filename,color=White,maxLines=1,
                                overflow=TextOverflow.Ellipsis)
                            Text(item.extension.uppercase()+" · "+
                                stringResource(R.string.experimental),
                                color=Secondary,fontSize=12.sp)
                        }
                        Icon(Icons.Outlined.KeyboardArrowRight,null,tint=Secondary)
                    }
                }
            }
            OutlinedButton(onClick=onClear){
                Icon(Icons.Outlined.DeleteOutline,null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.delete_session))
            }
        }
        OutlinedButton(onClick=onImportMultiple){
            Icon(Icons.Outlined.FileUpload,null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.select_file))
        }
    }
}
@Composable
private fun FormatsScreen(){
    val context=LocalContext.current
    val formats=remember(context){AndroidDecoderCatalog.read(context)}
    var query by rememberSaveable{mutableStateOf("")}
    val visible=remember(query,formats){
        formats.filter{query.isBlank()||it.suffix.contains(query.trim(),ignoreCase=true)}
    }
    Column(Modifier.fillMaxSize().padding(horizontal=20.dp,vertical=12.dp)){
        Text(stringResource(R.string.formats),fontSize=24.sp,fontWeight=FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.catalog_note),fontSize=13.sp,
            color=Secondary,lineHeight=20.sp)
        Spacer(Modifier.height(14.dp))
        OutlinedTextField(value=query,onValueChange={query=it},
            label={Text(stringResource(R.string.search_formats))},
            leadingIcon={Icon(Icons.Outlined.Search,null)},
            singleLine=true,modifier=Modifier.fillMaxWidth(),
            shape=RoundedCornerShape(13.dp))
        Spacer(Modifier.height(8.dp))
        androidx.compose.foundation.lazy.LazyColumn(
            modifier=Modifier.fillMaxWidth(),
            verticalArrangement=Arrangement.spacedBy(3.dp),
            contentPadding=PaddingValues(bottom=20.dp)
        ){
            items(visible.size){i->
                val f=visible[i]
                Row(Modifier.fillMaxWidth().padding(vertical=10.dp,horizontal=4.dp),
                    verticalAlignment=Alignment.CenterVertically){
                    Icon(Icons.Outlined.Description,null,tint=Secondary)
                    Spacer(Modifier.width(13.dp))
                    Text("."+f.suffix,color=White,fontSize=16.sp,modifier=Modifier.weight(1f))
                    Text(stringResource(R.string.experimental),color=Amber,fontSize=12.sp)
                }
                HorizontalDivider(color=Outline)
            }
        }
    }
}
@Composable
private fun SettingsScreen(onClear:()->Unit){
    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState())
        .padding(20.dp),verticalArrangement=Arrangement.spacedBy(17.dp)){
        Text(stringResource(R.string.settings_title),fontSize=24.sp,fontWeight=FontWeight.Bold)
        SettingsSection(Icons.Outlined.Lock,
            stringResource(R.string.privacy_title),
            stringResource(R.string.privacy_text))
        SettingsSection(Icons.Outlined.Info,
            stringResource(R.string.about_title),
            stringResource(R.string.about_text))
        SettingsSection(Icons.Outlined.Translate,
            stringResource(R.string.language_title),
            stringResource(R.string.language_text))
        OutlinedButton(onClick=onClear,modifier=Modifier.fillMaxWidth()){
            Icon(Icons.Outlined.DeleteOutline,null)
            Spacer(Modifier.width(9.dp))
            Text(stringResource(R.string.delete_session))
        }
        Text("SP-DECODE · 0.2.0-alpha",color=Secondary,fontSize=12.sp,
            modifier=Modifier.align(Alignment.CenterHorizontally))
    }
}
@Composable
private fun SettingsSection(icon:androidx.compose.ui.graphics.vector.ImageVector,
                            title:String,description:String) {
    Surface(color=Panel,shape=RoundedCornerShape(15.dp),modifier=Modifier.fillMaxWidth()){
        Row(Modifier.padding(17.dp),verticalAlignment=Alignment.Top){
            Icon(icon,null,tint=White,modifier=Modifier.size(23.dp))
            Spacer(Modifier.width(13.dp))
            Column(verticalArrangement=Arrangement.spacedBy(8.dp)){
                Text(title,color=White,fontWeight=FontWeight.SemiBold)
                Text(description,color=Secondary,fontSize=13.sp,lineHeight=19.sp)
            }
        }
    }
}
@Composable
private fun CardText(value:String) {
    Surface(color=Panel,shape=RoundedCornerShape(15.dp),modifier=Modifier.fillMaxWidth()){
        Text(value,modifier=Modifier.padding(20.dp),color=Secondary,fontSize=14.sp)
    }
}

@Composable
private fun BottomTabs(active:Int,onTab:(Int)->Unit) {
    val tabs=listOf(
        Triple(R.string.home,Icons.Outlined.Home,0),
        Triple(R.string.history,Icons.Outlined.History,1),
        Triple(R.string.formats,Icons.Outlined.Code,2),
        Triple(R.string.settings,Icons.Outlined.Settings,3)
    )
    HorizontalDivider(color=Outline)
    Row(Modifier.fillMaxWidth().heightIn(min=65.dp).padding(bottom=2.dp),
        verticalAlignment=Alignment.CenterVertically){
        tabs.forEach{(label,icon,index)->
            val selected=active==index
            Column(Modifier.weight(1f).clickable{onTab(index)}
                    .padding(vertical=9.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(4.dp)){
                Icon(icon,stringResource(label),
                    tint=if(selected)White else Secondary,modifier=Modifier.size(21.dp))
                Text(stringResource(label),fontSize=11.sp,
                    color=if(selected)White else Secondary,
                    maxLines=1,overflow=TextOverflow.Ellipsis)
            }
        }
    }
}
