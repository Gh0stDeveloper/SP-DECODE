package com.ghostdeveloper.spdecode

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.Context
import android.content.res.Configuration
import android.content.ActivityNotFoundException
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.viewModels
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.first
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.Locale

/**
 * First functional offline Android alpha.
 * No app-specific file paths, INTERNET permission, backend or original script
 * subprocess. Decoded history persists in app-private encrypted storage.
 */
class MainActivity : ComponentActivity() {
    private companion object { const val MAX_BYTES=1024*1024 }
    private val scope=CoroutineScope(SupervisorJob()+Dispatchers.Main.immediate)
    private var selectedLanguage by mutableStateOf("system")
    private var hideCredentials by mutableStateOf(false)
    private val settings get()=getSharedPreferences("spdecode-ui-preferences",MODE_PRIVATE)
    private var job:Job?=null
    private val historyStore by lazy { SecureDecodeHistory(applicationContext) }
    private val historyPreferences by lazy { HistoryPreferences(applicationContext) }
    private var retentionDays by mutableIntStateOf(0)
    private var historyLoad: Deferred<Unit>? = null
    private val sessionVm by viewModels<DecodeSessionViewModel>()
    private val recent get()=sessionVm.recent
    private var result:DecodeView?
        get()=sessionVm.current
        set(value){sessionVm.current=value}
    private var tab:Int
        get()=sessionVm.tab
        set(value){sessionVm.tab=value}
    private var busy by mutableStateOf(false)
    private var progressStage by mutableIntStateOf(0)
    private var progressFilename by mutableStateOf<String?>(null)
    private var progressPosition by mutableIntStateOf(1)
    private var progressTotal by mutableIntStateOf(1)
    private var importGeneration=0
    private var message by mutableStateOf<String?>(null)
    private var reveal:Boolean
        get()=sessionVm.reveal
        set(value){sessionVm.reveal=value}
    private var stagedExport:String?=null

    override fun attachBaseContext(base:Context) {
        val tag=base.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE)
            .getString("language","system") ?: "system"
        if(tag=="system") {
            super.attachBaseContext(base)
        }else {
            val locale=Locale.forLanguageTag(tag)
            val config=Configuration(base.resources.configuration)
            config.setLocale(locale)
            config.setLayoutDirection(locale)
            super.attachBaseContext(base.createConfigurationContext(config))
        }
    }

    private val picker=registerForActivityResult(ActivityResultContracts.OpenDocument()){uri->
        if(uri!=null)importFiles(listOf(uri))
    }
    private val multiPicker=registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()){uris->
        if(uris.isNotEmpty())importFiles(uris.take(BatchImportQueue.MAX_FILES))
    }
    private val exporter=registerForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")){uri->saveExport(uri)}

    private val jsonExporter=registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")){uri->
        saveExport(uri)
    }

    private fun saveExport(uri:Uri?){
        val text=stagedExport
        stagedExport=null
        if(uri!=null && text!=null)scope.launch{
            try{
                withContext(Dispatchers.IO){
                    contentResolver.openOutputStream(uri,"w")?.use{
                        it.write(text.toByteArray(Charsets.UTF_8))
                        it.flush()
                    }?:throw IOException("Destination unavailable")
                }
                toast(R.string.saved)
            }catch(_:Exception){toast(R.string.write_error)}
        }
    }

    private fun setLanguage(tag:String){
        if(!SupportedLanguages.supports(tag)||tag==selectedLanguage)return
        settings.edit().putString("language",tag).apply()
        selectedLanguage=tag
        recreate()
    }

    private fun openExternal(url:String){
        if(url !in setOf(
            "https://github.com/Gh0stDeveloper/SP-DECODE",
            "https://github.com/Gh0stDeveloper/SP-DECODE/issues",
            "https://t.me/Gh0stDeveloper",
            "https://t.me/CodeBreakersHub",
            "https://t.me/GhostDeve"
        ))return
        try {startActivity(Intent(Intent.ACTION_VIEW,Uri.parse(url)))}
        catch(_:ActivityNotFoundException){toast(R.string.read_error)}
    }

    override fun onCreate(savedInstanceState:Bundle?){
        super.onCreate(savedInstanceState)
        selectedLanguage=settings.getString("language","system") ?: "system"
        hideCredentials=settings.getBoolean("mask_credentials",false)
        @Suppress("DEPRECATION")
        window.statusBarColor=android.graphics.Color.BLACK
        @Suppress("DEPRECATION")
        window.navigationBarColor=android.graphics.Color.BLACK
        window.decorView.systemUiVisibility=0

        historyLoad = scope.async {
            try {
                val preferences = historyPreferences.values.first()
                retentionDays=preferences.retentionDays
                val saved=withContext(Dispatchers.IO) {
                    val days=preferences.retentionDays
                    if(days>0) historyStore.pruneOlderThan(
                        System.currentTimeMillis()-days.toLong()*86_400_000L)
                    historyStore.load()
                }
                // Process death: restore the last result by an opaque UUID only.
                val existingIds=recent.map{it.id}.toSet()
                saved.filterNot{it.id in existingIds}.forEach{recent.add(it)}
                if(result==null && preferences.selectedId!=null)
                    result=recent.firstOrNull{it.id==preferences.selectedId}
            }catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
        setContent {
            SpDecodeApp(
                activeTab=tab,
                current=result,
                session=recent,
                busy=busy,
                error=message,
                progressStage=progressStage,
                progressFilename=progressFilename,
                progressPosition=progressPosition,
                progressTotal=progressTotal,
                reveal=reveal,
                onTab={tab=it;reveal=false},
                onImport={picker.launch(arrayOf("*/*"))},
                onImportMultiple={multiPicker.launch(arrayOf("*/*"))},
                onCancel={cancelImport()},
                onReveal={reveal=it},
                onCopy={format->result?.let{copy(ResultPresentation.formatted(it.document,format))}},
                onExport={format->result?.let{export(ResultPresentation.formatted(it.document,format),it.filename,format)}},
                selectedLanguage=selectedLanguage,
                hideCredentials=hideCredentials,
                onLanguage={tag->setLanguage(tag)},
                onMaskCredentials={value->hideCredentials=value;settings.edit().putBoolean("mask_credentials",value).apply()},
                onExternalLink={url->openExternal(url)},
                onSelect={selectResult(it)},
                onClear={clearHistory()},
                onDeleteSelected={ids->deleteHistory(ids)},
                onFavorite={id,favorite->updateFavorite(id,favorite)},
                retentionDays=retentionDays,
                onRetention={days->setRetention(days)},
                onDismissError={message=null},
            )
        }
        if(savedInstanceState==null)handleExternalIntent(intent)
    }

    override fun onNewIntent(intent:Intent){
        super.onNewIntent(intent)
        setIntent(intent)
        handleExternalIntent(intent)
    }

    @Suppress("DEPRECATION")
    private fun handleExternalIntent(incoming:Intent?){
        if(incoming==null)return
        val uris: List<Uri> = when(incoming.action){
            Intent.ACTION_VIEW->listOfNotNull(incoming.data)
            Intent.ACTION_SEND->listOfNotNull(incoming.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri)
            Intent.ACTION_SEND_MULTIPLE->
                incoming.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.take(BatchImportQueue.MAX_FILES).orEmpty()
            else->emptyList()
        }
        if(uris.isNotEmpty())importFiles(uris.take(BatchImportQueue.MAX_FILES))
    }

    private fun cancelImport() {
        // An obsolete worker must not close the new import's progress dialog.
        importGeneration++
        job?.cancel()
        job=null
        busy=false
        progressFilename=null
    }

    private fun selectResult(entry:DecodeView) {
        result=entry
        tab=0
        reveal=false
        scope.launch {
            try{historyPreferences.setSelectedId(entry.id)}
            catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
    }

    private fun importFiles(uris:List<Uri>){
        job?.cancel()
        val generation=++importGeneration
        val inputs=uris.take(BatchImportQueue.MAX_FILES)
        if(inputs.isEmpty())return
        job=scope.launch {
            busy=true
            progressStage=0
            progressFilename=null
            progressPosition=1
            progressTotal=inputs.size
            message=null
            reveal=false
            try {
                historyLoad?.await()
                val report=BatchImportQueue.process(inputs){uri,index,total->
                    progressPosition=index
                    progressTotal=total
                    progressStage=0
                    val name=withContext(Dispatchers.IO){displayName(uri)}
                    progressFilename=name
                    val supported=AndroidDecoderCatalog.detect(
                        name,AndroidDecoderCatalog.read(this@MainActivity))
                        ?:throw DecodeFailure(R.string.unsupported)
                    val input=withContext(Dispatchers.IO){readBounded(uri)}
                    progressStage=1
                    val text=withContext(Dispatchers.Default){
                        AndroidOfflineDecoderRouter.decode(this@MainActivity,name,input)
                    }?:throw DecodeFailure(R.string.unsupported_variant_message)
                    val processed=DecodeView(name,supported.suffix,text,input.size)
                    progressStage=2
                    val saved=try {
                        withContext(Dispatchers.IO){historyStore.save(processed)}
                        true
                    }catch(e:CancellationException){throw e}
                    catch(_:Exception){false}
                    result=processed
                    recent.add(0,processed)
                    if(!saved)toast(R.string.history_storage_error)
                    // Preference failure must not misreport a valid decoded file
                    // as failed after its encrypted record has already been saved.
                    try { historyPreferences.setSelectedId(processed.id) }
                    catch(e:CancellationException){throw e}
                    catch(_:Exception){toast(R.string.history_storage_error)}
                    tab=0
                }
                if(generation==importGeneration && report.failures>0) {
                    message=getString(R.string.batch_import_summary,
                        report.successes,report.failures)
                    tab=0
                }
            }catch(e:CancellationException){throw e}
            catch(_:Exception){if(generation==importGeneration){
                message=getString(R.string.read_error);tab=0
            }}
            finally {
                if(generation==importGeneration) {
                    busy=false
                    progressFilename=null
                    progressPosition=1
                    progressTotal=1
                }
            }
        }
    }

    private fun updateFavorite(id:String,favorite:Boolean) {
        scope.launch {
            try {
                historyLoad?.await()
                val updated=withContext(Dispatchers.IO) {
                    historyStore.setFavorite(id,favorite)
                }
                val index=recent.indexOfFirst{it.id==id}
                if(index>=0)recent[index]=updated
                if(result?.id==id)result=updated
            }catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
    }

    private fun setRetention(days:Int) {
        if(days !in HistoryPreferences.choices)return
        scope.launch {
            try {
                historyLoad?.await()
                historyPreferences.setRetentionDays(days)
                retentionDays=days
                if(days>0) {
                    val pruned=withContext(Dispatchers.IO) {
                        historyStore.pruneOlderThan(
                            System.currentTimeMillis()-days.toLong()*86_400_000L)
                    }
                    recent.removeAll { it.id in pruned }
                    if(result?.id in pruned) {
                        result=null
                        historyPreferences.setSelectedId(null)
                    }
                }
            }catch(_:CancellationException){throw CancellationException()}
            catch(_:Exception){toast(R.string.history_storage_error)}
        }
    }

    private fun clearHistory() {
        scope.launch {
            try {
                historyLoad?.await()
                withContext(Dispatchers.IO) { historyStore.clearAll() }
                historyPreferences.setSelectedId(null)
                recent.clear()
                result = null
                reveal = false
            } catch (_: Exception) {
                toast(R.string.history_storage_error)
            }
        }
    }

    private fun deleteHistory(ids:Set<String>) {
        scope.launch {
            try {
                historyLoad?.await()
                val targets = if (ids.isEmpty()) recent.map { it.id }.toSet() else ids
                if (targets.isEmpty()) return@launch
                withContext(Dispatchers.IO) { historyStore.delete(targets) }
                recent.removeAll { it.id in targets }
                if (result?.id in targets) {
                    historyPreferences.setSelectedId(null)
                    result = null
                    reveal = false
                }
            } catch (_: Exception) {
                toast(R.string.history_storage_error)
                // Resync after a partial disk failure, avoiding a false success.
                val saved = runCatching {
                    withContext(Dispatchers.IO) { historyStore.load() }
                }.getOrNull()
                if (saved != null) {
                    recent.clear()
                    recent.addAll(saved)
                    if (result != null && recent.none { it.id == result?.id }) result = null
                }
            }
        }
    }

    private class DecodeFailure(val stringId:Int):Exception()
    private fun readBounded(uri:Uri):ByteArray{
        val stream=contentResolver.openInputStream(uri)?:throw DecodeFailure(R.string.read_error)
        return stream.use {input->
            val out=ByteArrayOutputStream()
            val buf=ByteArray(8192)
            while(true){
                val n=input.read(buf)
                if(n<0)break
                if(out.size().toLong()+n>MAX_BYTES)throw DecodeFailure(R.string.file_too_large)
                out.write(buf,0,n)
            }
            out.toByteArray()
        }
    }
    private fun displayName(uri:Uri):String{
        try{
            contentResolver.query(uri,arrayOf(OpenableColumns.DISPLAY_NAME),
                null,null,null)?.use{cursor->
                if(cursor.moveToFirst()) {
                    val i=cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if(i>=0)return cursor.getString(i).take(220)
                }
            }
        }catch(_:Exception){}
        return uri.lastPathSegment?.substringAfterLast('/')?.take(220) ?:"file"
    }
    private fun copy(text:String){
        val manager=getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        val clip=ClipData.newPlainText("SP-DECODE",text)
        if(Build.VERSION.SDK_INT>=33){
            clip.description.extras=PersistableBundle().apply{
                putBoolean("android.content.extra.IS_SENSITIVE",true)
            }
        }
        manager.setPrimaryClip(clip)
        toast(R.string.copied)
    }
    private fun export(text:String,filename:String,format:ResultExport){
        stagedExport=text
        val safe=filename.substringBeforeLast('.').replace(Regex("[^A-Za-z0-9._-]"),"_")
            .take(50).ifEmpty{"spdecode"}
        if(format==ResultExport.JSON) jsonExporter.launch("$safe-decoded.json")
        else exporter.launch("$safe-decoded.txt")
    }
    private fun toast(id:Int)=Toast.makeText(this,id,Toast.LENGTH_SHORT).show()

    override fun onStop(){
        reveal=false
        super.onStop()
    }
    override fun onDestroy(){
        job?.cancel()
        scope.cancel()
        super.onDestroy()
    }
}
