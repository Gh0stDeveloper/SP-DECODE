package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val Pane=Color(0xFF242424)
private val MutedText=Color(0xFFABABAB)
private val TitleText=Color(0xFFF7F7F7)
private val SurfaceLine=Color(0xFF343434)

/** Actual per-app locale choice, credited URLs are verified from README. */
@Composable
fun FunctionalSettingsPanel(
    language:String,
    maskCredentials:Boolean,
    onLanguage:(String)->Unit,
    onMaskCredentials:(Boolean)->Unit,
    onClear:()->Unit,
    onExternalLink:(String)->Unit,
){
    var clearDialog by remember { mutableStateOf(false) }
    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState())
            .padding(horizontal=20.dp,vertical=12.dp),
        verticalArrangement=Arrangement.spacedBy(14.dp),
    ){
        Text(stringResource(R.string.settings_title),fontSize=24.sp,
            fontWeight=FontWeight.Bold,color=TitleText)

        SettingsCard {
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Language,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.language_title),color=TitleText,
                    fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Text(stringResource(R.string.language_pick_description),
                color=MutedText,fontSize=13.sp)
            val options=listOf(
                "system" to stringResource(R.string.language_system),
                "es" to "Español",
                "en" to "English",
                "pt-BR" to "Português (Brasil)",
                "ar" to "العربية",
            )
            options.forEach{(tag,title)->
                Row(
                    modifier=Modifier.fillMaxWidth().clickable {onLanguage(tag)}
                        .padding(vertical=5.dp),
                    verticalAlignment=Alignment.CenterVertically,
                ){
                    RadioButton(
                        selected=language==tag,
                        onClick={onLanguage(tag)},
                        colors=RadioButtonDefaults.colors(
                            selectedColor=TitleText,unselectedColor=MutedText
                        )
                    )
                    Spacer(Modifier.width(10.dp))
                    Text(title,color=TitleText,fontSize=14.sp)
                }
            }
        }
        SettingsCard{
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Visibility,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.result_preferences_title),
                    color=TitleText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Row(verticalAlignment=Alignment.CenterVertically){
                Column(modifier=Modifier.weight(1f)){
                    Text(stringResource(R.string.mask_passwords_title),color=TitleText)
                    Text(stringResource(R.string.mask_passwords_detail),
                        color=MutedText,fontSize=12.sp,lineHeight=18.sp)
                }
                Switch(
                    checked=maskCredentials,onCheckedChange=onMaskCredentials,
                    colors=SwitchDefaults.colors(checkedThumbColor=Color.Black,
                        checkedTrackColor=TitleText)
                )
            }
            Text(stringResource(R.string.export_security_note),
                color=MutedText,fontSize=12.sp,lineHeight=17.sp)
        }
        SettingsCard{
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Lock,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.privacy_title),color=TitleText,
                    fontWeight=FontWeight.SemiBold)
            }
            Text(stringResource(R.string.privacy_text),color=MutedText,
                fontSize=13.sp,lineHeight=19.sp)
            OutlinedButton(onClick={clearDialog=true},modifier=Modifier.fillMaxWidth()){
                Icon(Icons.Outlined.DeleteOutline,null)
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.delete_session))
            }
        }
        SettingsCard{
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.Terminal,null,tint=TitleText)
                Spacer(Modifier.width(10.dp))
                Text(stringResource(R.string.developer_credits),color=TitleText,
                    fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            }
            Text("Ghost Developer · @Gh0stDeveloper",color=TitleText,fontSize=14.sp)
            Text(stringResource(R.string.contribute_invitation),
                color=MutedText,fontSize=13.sp,lineHeight=19.sp)
            LinkRow(Icons.Outlined.Code,"Repositorio · GitHub",
                "https://github.com/Gh0stDeveloper/SP-DECODE",onExternalLink)
            LinkRow(Icons.Outlined.AccountCircle,
                stringResource(R.string.contact_developer),
                "https://t.me/Gh0stDeveloper",onExternalLink)
            LinkRow(Icons.Outlined.Groups,
                stringResource(R.string.telegram_group),
                "https://t.me/CodeBreakersHub",onExternalLink)
            LinkRow(Icons.Outlined.Campaign,
                stringResource(R.string.telegram_channel),
                "https://t.me/GhostDeve",onExternalLink)
            LinkRow(Icons.Outlined.BugReport,
                stringResource(R.string.report_issue),
                "https://github.com/Gh0stDeveloper/SP-DECODE/issues",onExternalLink)
        }
        Text(stringResource(R.string.about_text),color=MutedText,fontSize=12.sp)
        Text("SP-DECODE · 0.3.0-alpha",color=MutedText,fontSize=12.sp,
            modifier=Modifier.align(Alignment.CenterHorizontally))
        Spacer(Modifier.height(6.dp))
    }
    if(clearDialog) AlertDialog(
        onDismissRequest={clearDialog=false},
        title={Text(stringResource(R.string.clear_confirm_title))},
        text={Text(stringResource(R.string.clear_confirm_detail))},
        confirmButton={
            TextButton(onClick={clearDialog=false;onClear()}){
                Text(stringResource(R.string.delete_session))
            }
        },
        dismissButton={TextButton(onClick={clearDialog=false}){
            Text(stringResource(R.string.cancel))
        }},
        containerColor=Pane,
    )
}

@Composable private fun SettingsCard(content:@Composable ColumnScope.()->Unit){
    Surface(
        color=Pane,shape=RoundedCornerShape(16.dp),
        modifier=Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(12.dp),
            content=content)
    }
}
@Composable private fun LinkRow(
    icon:androidx.compose.ui.graphics.vector.ImageVector,
    text:String,url:String,onExternalLink:(String)->Unit
){
    Surface(
        modifier=Modifier.fillMaxWidth().clickable{onExternalLink(url)},
        color=Pane,shape=RoundedCornerShape(8.dp)
    ){
        Row(Modifier.fillMaxWidth().padding(vertical=9.dp),
            verticalAlignment=Alignment.CenterVertically){
            Icon(icon,null,tint=MutedText,modifier=Modifier.size(20.dp))
            Spacer(Modifier.width(12.dp))
            Text(text,color=TitleText,modifier=Modifier.weight(1f),fontSize=13.sp)
            Icon(Icons.Outlined.OpenInNew,null,tint=MutedText,
                modifier=Modifier.size(18.dp))
        }
    }
}
