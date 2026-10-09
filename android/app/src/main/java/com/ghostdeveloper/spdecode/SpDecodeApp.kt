package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
    onCopy:(ResultExport)->Unit,
    onExport:(ResultExport)->Unit,
    selectedLanguage:String,
    hideCredentials:Boolean,
    onLanguage:(String)->Unit,
    onMaskCredentials:(Boolean)->Unit,
    onExternalLink:(String)->Unit,
    onSelect:(DecodeView)->Unit,
    onClear:()->Unit,
    onDeleteSelected:(Set<String>)->Unit,
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
                    0->HomeScreen(current,session,busy,reveal,hideCredentials,onImport,onCancel,onReveal,
                        onCopy={dialog="copy"},onExport={dialog="export"},onSelect=onSelect)
                    1->HistoryScreen(session,onSelect,onDeleteSelected,onClear,onImportMultiple)
                    2->FormatsScreen()
                    else->FunctionalSettingsPanel(selectedLanguage,hideCredentials,
                        onLanguage,onMaskCredentials,onClear,onExternalLink)
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
                    Column(verticalArrangement=Arrangement.spacedBy(10.dp)) {
                        Text(stringResource(R.string.privacy_warning),
                            color=Secondary,fontSize=13.sp)
                        listOf(
                            Triple(ResultExport.JSON,R.string.json_option,Icons.Outlined.DataObject),
                            Triple(ResultExport.ORDERED,R.string.ordered_option,Icons.Outlined.FormatListBulleted),
                            Triple(ResultExport.ORIGINAL,R.string.original_option,Icons.Outlined.Code)
                        ).forEach { (format,label,icon)->
                            OutlinedButton(
                                modifier=Modifier.fillMaxWidth(),
                                onClick={
                                    if(copy)onCopy(format)else onExport(format)
                                    dialog=null
                                }
                            ){
                                Icon(icon,null)
                                Spacer(Modifier.width(9.dp))
                                Text(stringResource(label))
                            }
                        }
                    }
                },
                confirmButton={TextButton(onClick={dialog=null}){
                    Text(stringResource(R.string.cancel))
                }},
                containerColor=Panel,
                titleContentColor=White,
                textContentColor=White,
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
            Icon(Icons.Outlined.Tune,stringResource(R.string.options),tint=Secondary)
        }
    }
}

@Composable
private fun HomeScreen(
    current:DecodeView?,
    session:List<DecodeView>,
    busy:Boolean,
    reveal:Boolean,
    hideCredentials:Boolean,
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
        CompleteResultCard(current,reveal,hideCredentials,onReveal,onCopy,onExport)
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
private fun HistoryScreen(
    session: List<DecodeView>,
    onSelect: (DecodeView) -> Unit,
    onDeleteSelected: (Set<String>) -> Unit,
    onDeleteAll: () -> Unit,
    onImportMultiple: () -> Unit,
) {
    var selecting by remember { mutableStateOf(false) }
    val selected = remember { mutableStateListOf<String>() }
    var deletion by remember { mutableStateOf<Set<String>?>(null) }
    var deletingAll by remember { mutableStateOf(false) }
    LaunchedEffect(session.map { it.id }) {
        selected.retainAll(session.map { it.id }.toSet())
        if (session.isEmpty()) selecting = false
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(13.dp),
        contentPadding = PaddingValues(horizontal = 20.dp, vertical = 16.dp),
    ) {
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.history), color = White,
                    fontSize = 24.sp, fontWeight = FontWeight.Bold,
                    modifier = Modifier.weight(1f))
                if (session.isNotEmpty()) {
                    TextButton(onClick = {
                        selecting = !selecting
                        selected.clear()
                    }) {
                        Text(stringResource(if (selecting) R.string.cancel
                            else R.string.history_select))
                    }
                }
            }
        }
        item { Text(stringResource(R.string.session_only), color = Secondary, fontSize = 13.sp) }
        if (session.isEmpty()) {
            item { CardText(stringResource(R.string.empty_history)) }
        } else {
            if (selecting) item {
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    TextButton(onClick = {
                        if (selected.size == session.size) selected.clear()
                        else {
                            selected.clear()
                            selected.addAll(session.map { it.id })
                        }
                    }) {
                        Text(stringResource(if (selected.size == session.size)
                            R.string.history_deselect_all else R.string.history_select_all))
                    }
                    Spacer(Modifier.weight(1f))
                    Text(stringResource(R.string.history_selected_count, selected.size),
                        color = Secondary, fontSize = 12.sp)
                }
            }
            items(session, key = { it.id }) { entry ->
                val checked = entry.id in selected
                Surface(
                    color = Panel, shape = RoundedCornerShape(14.dp),
                    modifier = Modifier.fillMaxWidth().clickable {
                        if (selecting) {
                            if (checked) selected.remove(entry.id) else selected.add(entry.id)
                        } else onSelect(entry)
                    },
                ) {
                    Row(Modifier.padding(horizontal = 12.dp, vertical = 12.dp),
                        verticalAlignment = Alignment.CenterVertically) {
                        if (selecting) {
                            Checkbox(checked = checked, onCheckedChange = {
                                if (it) { if (!checked) selected.add(entry.id) }
                                else selected.remove(entry.id)
                            })
                        } else Icon(Icons.Outlined.InsertDriveFile, null, tint = White)
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(entry.filename, color = White, maxLines = 1,
                                overflow = TextOverflow.Ellipsis)
                            Text("." + entry.extension + " · " +
                                stringResource(R.string.experimental),
                                color = Secondary, fontSize = 12.sp)
                        }
                        if (!selecting) {
                            IconButton(onClick = { deletion = setOf(entry.id) }) {
                                Icon(Icons.Outlined.DeleteOutline,
                                    stringResource(R.string.history_delete_one), tint = Secondary)
                            }
                        }
                    }
                }
            }
            item {
                if (selecting) {
                    Button(onClick = { deletion = selected.toSet() },
                        enabled = selected.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth()) {
                        Icon(Icons.Outlined.DeleteOutline, null)
                        Spacer(Modifier.width(8.dp))
                        Text(stringResource(R.string.history_delete_selected))
                    }
                } else OutlinedButton(onClick = {
                    deletion = session.map { it.id }.toSet()
                    deletingAll = true
                }) {
                    Icon(Icons.Outlined.DeleteOutline, null)
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.delete_session))
                }
            }
        }
        item {
            OutlinedButton(onClick = onImportMultiple) {
                Icon(Icons.Outlined.FileUpload, null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.select_file))
            }
        }
    }
    if (deletion != null) AlertDialog(
        onDismissRequest = { deletion = null },
        title = { Text(stringResource(R.string.clear_confirm_title)) },
        text = { Text(stringResource(R.string.history_delete_confirm, deletion!!.size)) },
        confirmButton = {
            TextButton(onClick = {
                val ids = deletion.orEmpty()
                deletion = null
                selected.clear()
                selecting = false
                if (deletingAll) onDeleteAll()
                else if (ids.isNotEmpty()) onDeleteSelected(ids)
                deletingAll = false
            }) { Text(stringResource(R.string.history_delete_selected)) }
        },
        dismissButton = { TextButton(onClick = { deletion = null }) {
            Text(stringResource(R.string.cancel))
        } },
        containerColor = Panel,
    )
}

@Composable
private fun FormatsScreen() {
    val context = LocalContext.current
    val formats = remember(context) { AndroidDecoderCatalog.read(context) }
    var query by rememberSaveable { mutableStateOf("") }
    val groups = remember(query, formats) {
        formats.groupBy { it.appName }.toList()
            .filter { (name, entries) ->
                query.isBlank() || name.contains(query.trim(), ignoreCase = true) ||
                    entries.any { it.suffix.contains(query.trim(), ignoreCase = true) }
            }
            .sortedBy { it.first.lowercase(java.util.Locale.ROOT) }
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 12.dp)) {
        Text(stringResource(R.string.formats), fontSize = 24.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(stringResource(R.string.catalog_note), fontSize = 13.sp,
            color = Secondary, lineHeight = 20.sp)
        Spacer(Modifier.height(14.dp))
        OutlinedTextField(value = query, onValueChange = { query = it },
            label = { Text(stringResource(R.string.search_formats)) },
            leadingIcon = { Icon(Icons.Outlined.Search, null) },
            singleLine = true, modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(13.dp))
        Spacer(Modifier.height(8.dp))
        LazyColumn(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(3.dp),
            contentPadding = PaddingValues(bottom = 20.dp),
        ) {
            items(groups, key = { it.first }) { (appName, extensions) ->
                Row(Modifier.fillMaxWidth().padding(vertical = 12.dp, horizontal = 4.dp),
                    verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Outlined.Description, null, tint = Secondary)
                    Spacer(Modifier.width(13.dp))
                    Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                        Text(appName, color = White, fontSize = 15.sp,
                            fontWeight = FontWeight.SemiBold)
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            extensions.sortedBy { it.suffix }.forEach { ext ->
                                Text("." + ext.suffix, color = White, fontSize = 12.sp,
                                    modifier = Modifier.background(Raised,
                                        RoundedCornerShape(7.dp))
                                        .padding(horizontal = 9.dp, vertical = 5.dp))
                            }
                        }
                    }
                    Spacer(Modifier.width(5.dp))
                    Text(stringResource(R.string.experimental), color = Amber, fontSize = 11.sp)
                }
                HorizontalDivider(color = Outline)
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
