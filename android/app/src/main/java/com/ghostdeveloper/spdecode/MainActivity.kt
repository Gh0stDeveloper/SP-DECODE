package com.ghostdeveloper.spdecode

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PersistableBundle
import android.provider.OpenableColumns
import android.widget.Toast
import androidx.activity.ComponentActivity
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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException

/**
 * First functional offline Android alpha.
 * No app-specific file paths, INTERNET permission, backend or original script
 * subprocess. Session records never persist cleartext to storage.
 */
class MainActivity : ComponentActivity() {
    private companion object { const val MAX_BYTES=1024*1024 }
    private val scope=CoroutineScope(SupervisorJob()+Dispatchers.Main.immediate)
    private var job:Job?=null
    private val recent=mutableStateListOf<DecodeView>()
    private var result by mutableStateOf<DecodeView?>(null)
    private var tab by mutableIntStateOf(0)
    private var busy by mutableStateOf(false)
    private var message by mutableStateOf<String?>(null)
    private var reveal by mutableStateOf(false)
    private var stagedExport:String?=null

    private val picker=registerForActivityResult(ActivityResultContracts.OpenDocument()){uri->
        if(uri!=null)importFiles(listOf(uri))
    }
    private val multiPicker=registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()){uris->
        if(uris.isNotEmpty())importFiles(uris.take(10))
    }
    private val exporter=registerForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")){uri->
        val text=stagedExport
        stagedExport=null
        if(uri!=null && text!=null) {
            scope.launch {
                try{
                    withContext(Dispatchers.IO) {
                        contentResolver.openOutputStream(uri,"w")?.use {
                            it.write(text.toByteArray(Charsets.UTF_8))
                            it.flush()
                        }?:throw IOException("Destination unavailable")
                    }
                    toast(R.string.saved)
                }catch(_:Exception){toast(R.string.write_error)}
            }
        }
    }

    override fun onCreate(savedInstanceState:Bundle?){
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION")
        window.statusBarColor=android.graphics.Color.BLACK
        @Suppress("DEPRECATION")
        window.navigationBarColor=android.graphics.Color.BLACK
        window.decorView.systemUiVisibility=0

        setContent {
            SpDecodeApp(
                activeTab=tab,
                current=result,
                session=recent,
                busy=busy,
                error=message,
                reveal=reveal,
                onTab={tab=it;reveal=false},
                onImport={picker.launch(arrayOf("*/*"))},
                onImportMultiple={multiPicker.launch(arrayOf("*/*"))},
                onCancel={job?.cancel();busy=false},
                onReveal={reveal=it},
                onCopy={original->result?.let{copy(if(original)it.rawText else it.redactedText)}},
                onExport={original->result?.let{export(if(original)it.rawText else it.redactedText,it.filename)}},
                onSelect={result=it;tab=0;reveal=false},
                onClear={recent.clear();result=null;reveal=false},
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
        val uris:List<Uri>=when(incoming.action){
            Intent.ACTION_VIEW->listOfNotNull(incoming.data)
            Intent.ACTION_SEND->listOfNotNull(incoming.getParcelableExtra(Intent.EXTRA_STREAM) as? Uri)
            Intent.ACTION_SEND_MULTIPLE->
                incoming.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)?.take(10).orEmpty()
            else->emptyList()
        }
        if(uris.isNotEmpty())importFiles(uris)
    }

    private fun importFiles(uris:List<Uri>){
        job?.cancel()
        job=scope.launch {
            busy=true
            message=null
            reveal=false
            try {
                for(uri in uris.take(10)){
                    val processed=withContext(Dispatchers.IO){
                        val name=displayName(uri)
                        val supported=AndroidDecoderCatalog.detect(name,AndroidDecoderCatalog.read(this@MainActivity))
                        if(supported==null)throw DecodeFailure(R.string.unsupported)
                        val input=readBounded(uri)
                        val text=withContext(Dispatchers.Default){
                            AndroidOfflineDecoderRouter.decode(this@MainActivity,name,input)
                        }?:throw DecodeFailure(R.string.import_error)
                        DecodeView(name,supported.suffix,text,input.size)
                    }
                    result=processed
                    recent.removeAll{it.filename==processed.filename}
                    recent.add(0,processed)
                    while(recent.size>12)recent.removeAt(recent.lastIndex)
                    tab=0
                }
            }catch(_:CancellationException){throw CancellationException()}
            catch(e:DecodeFailure){message=getString(e.stringId)}
            catch(_:Exception){message=getString(R.string.read_error)}
            finally{busy=false}
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
    private fun export(text:String,filename:String){
        stagedExport=text
        val safe=filename.substringBeforeLast('.').replace(Regex("[^A-Za-z0-9._-]"),"_")
            .take(50).ifEmpty{"spdecode"}
        exporter.launch("$safe-decoded.txt")
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
