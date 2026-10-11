package com.ghostdeveloper.spdecode.parity

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Data-only HCCFG engine ported from _hc_hccfg.py, kept separate from legacy
 * HcPort. Never guesses other formats, executes code or uses network access.
 * A valid AEAD authentication tag is required before accepting sections.
 *
 * External passwords are accepted only through the per-file S.4 opt-in route;
 * Android never guesses secrets or fetches device identity silently.
 */
internal object HcHccfgPort {
    private val p=LegacyPortPrimitives
    private val pkg="xyz.easypro.httpcustom".toByteArray()
    private val outerAad="HCX1|xyz.easypro.httpcustom|1".toByteArray()
    private val outerSeed="hc-envelope-seal-v1 xyz.easypro.httpcustom".toByteArray()
    private val outerSalt="hc-envelope-seal-salt-v1".toByteArray()
    private val outerInfo="hc-envelope-seal-info-v1".toByteArray()
    private val v3=p.hex("88702df6ae8c089c9478b8cd2bd3f30961b3574a58063d024bdc50f6b779e26f")
    private val n7=p.hex("9ba7ff3baf33db7aad807a86574b7ca55bef2f048ead51f3a1fe0cff389db3b3")
    private val c0=p.hex(
        "95dd433d7e4a0be02d55cc62553edcfc8f077fe780be5a7da7f861c2558dc181"+
        "38cabb40b2f81a5a30b11a97cbcf0fed755aa8c2b5495e9bc0c1902077a4cd92"
    )
    private val schemaVersions=mapOf(
        756 to "7.9.21",759 to "7.9.24",766 to "7.9.28",789 to "7.10.7",
        810 to "7.10.12",831 to "7.10.19",848 to "7.10.25",
        859 to "7.11.1",864 to "7.11.8",885 to "7.11.19"
    )
    private val protectionNames=mapOf(
        "a" to "accessMode","c" to "expiryEnabled","d" to "expiryTime",
        "e" to "noteEnabled","f" to "hwidLockEnabled","g" to "hwids",
        "h" to "loginHwidEnabled","j" to "loginHwidAuthorizationRequired",
        "l" to "mobileDataOnly","m" to "blockRoot","o" to "providerLockEnabled",
        "p" to "providerCodes","v" to "note"
    )
    private val polyMod=BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5))
    private val mask128=BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)
    private val zero=byteArrayOf(0)
    private fun utf(s:String)=s.toByteArray(Charsets.UTF_8)
    private fun bytes(vararg parts:ByteArray):ByteArray=ByteArrayOutputStream().apply {
        parts.forEach { write(it) }
    }.toByteArray()
    private fun sha(data:ByteArray)=MessageDigest.getInstance("SHA-256").digest(data)
    private fun mac(key:ByteArray,msg:ByteArray):ByteArray=Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key,"HmacSHA256"));doFinal(msg)
    }
    private fun hkdf(ikm:ByteArray,salt:ByteArray,info:ByteArray):ByteArray {
        val prk=mac(salt,ikm)
        return mac(prk,bytes(info,byteArrayOf(1))).copyOf(32)
    }
    private fun word(a:ByteArray,off:Int):Int =
        (a[off].toInt() and 255) or ((a[off+1].toInt() and 255) shl 8) or
        ((a[off+2].toInt() and 255) shl 16) or ((a[off+3].toInt() and 255) shl 24)
    private fun putWord(a:ByteArray,off:Int,n:Int){
        for(i in 0..3)a[off+i]=(n ushr (8*i)).toByte()
    }
    private fun rounds(s:IntArray) {
        fun qr(a:Int,b:Int,c:Int,d:Int) {
            s[a]+=s[b];s[d]=Integer.rotateLeft(s[d] xor s[a],16)
            s[c]+=s[d];s[b]=Integer.rotateLeft(s[b] xor s[c],12)
            s[a]+=s[b];s[d]=Integer.rotateLeft(s[d] xor s[a],8)
            s[c]+=s[d];s[b]=Integer.rotateLeft(s[b] xor s[c],7)
        }
        repeat(10){
            qr(0,4,8,12);qr(1,5,9,13);qr(2,6,10,14);qr(3,7,11,15)
            qr(0,5,10,15);qr(1,6,11,12);qr(2,7,8,13);qr(3,4,9,14)
        }
    }
    private fun state(key:ByteArray,nonce:ByteArray,counter:Int?=null):IntArray {
        require(key.size==32 && nonce.size==(if(counter==null)16 else 12))
        val s=IntArray(16)
        val constants=utf("expand 32-byte k")
        for(i in 0..3)s[i]=word(constants,i*4)
        for(i in 0..7)s[i+4]=word(key,i*4)
        if(counter==null){for(i in 0..3)s[i+12]=word(nonce,i*4)}
        else{s[12]=counter;for(i in 0..2)s[i+13]=word(nonce,i*4)}
        return s
    }
    private fun hchacha(key:ByteArray,nonce:ByteArray):ByteArray {
        val s=state(key,nonce)
        rounds(s)
        return ByteArray(32).also {
            val idx=intArrayOf(0,1,2,3,12,13,14,15)
            for(i in idx.indices)putWord(it,4*i,s[idx[i]])
        }
    }
    private fun chachaBlock(key:ByteArray,nonce:ByteArray,count:Int):ByteArray {
        val init=state(key,nonce,count);val s=init.clone()
        rounds(s)
        return ByteArray(64).also {
            for(i in 0..15)putWord(it,4*i,s[i]+init[i])
        }
    }
    private fun xor(data:ByteArray,key:ByteArray,nonce:ByteArray):ByteArray {
        require(data.size<=p.MAX_INPUT && key.size==32 && nonce.size==24)
        val sub=hchacha(key,nonce.copyOfRange(0,16))
        val n12=bytes(ByteArray(4),nonce.copyOfRange(16,24))
        return ByteArray(data.size).also {out->
            var off=0;var counter=1
            while(off<data.size){
                val block=chachaBlock(sub,n12,counter++)
                val n=minOf(64,data.size-off)
                for(i in 0 until n)out[off+i]=(data[off+i].toInt() xor block[i].toInt()).toByte()
                off+=n
            }
        }
    }
    private fun le(value:ByteArray)=BigInteger(1,value.reversedArray())
    private fun leBytes(value:BigInteger,n:Int):ByteArray {
        val big=value.toByteArray().reversedArray()
        return ByteArray(n).also {big.copyInto(it,0,0,minOf(n,big.size))}
    }
    private fun pad16(value:ByteArray):ByteArray=
        ByteArray((16-value.size%16)%16)
    private fun longLittle(n:Long):ByteArray=ByteArray(8).also {a->
        for(i in 0..7)a[i]=(n ushr (8*i)).toByte()
    }
    private fun poly(msg:ByteArray,oneTimeKey:ByteArray):ByteArray {
        require(oneTimeKey.size==32)
        val r=oneTimeKey.copyOfRange(0,16)
        for(i in intArrayOf(3,7,11,15))r[i]=(r[i].toInt() and 15).toByte()
        for(i in intArrayOf(4,8,12))r[i]=(r[i].toInt() and 252).toByte()
        val rInt=le(r);val pad=le(oneTimeKey.copyOfRange(16,32))
        var acc=BigInteger.ZERO
        var off=0
        while(off<msg.size){
            val n=minOf(16,msg.size-off)
            val part=ByteArray(n+1)
            msg.copyInto(part,0,off,off+n);part[n]=1
            acc=acc.add(le(part)).multiply(rInt).mod(polyMod)
            off+=n
        }
        return leBytes(acc.add(pad).and(mask128),16)
    }
    private fun xdec(key:ByteArray,nonce:ByteArray,aad:ByteArray,crypt:ByteArray):ByteArray {
        require(key.size==32 && nonce.size==24 && crypt.size>=16 && crypt.size<=p.MAX_INPUT)
        val sub=hchacha(key,nonce.copyOfRange(0,16))
        val n12=bytes(ByteArray(4),nonce.copyOfRange(16,24))
        val ct=crypt.copyOfRange(0,crypt.size-16)
        val tag=crypt.copyOfRange(crypt.size-16,crypt.size)
        val otk=chachaBlock(sub,n12,0).copyOf(32)
        val expected=poly(bytes(aad,pad16(aad),ct,pad16(ct),
            longLittle(aad.size.toLong()),longLittle(ct.size.toLong())),otk)
        require(MessageDigest.isEqual(expected,tag)){"HCCFG authentication failed"}
        return xor(ct,key,nonce)
    }
    private fun parseObject(data:ByteArray):JSONObject=JSONObject(p.utf8(data))
    private fun c0hash(data:ByteArray)=sha(bytes(c0,data))
    private fun openOuter(data:ByteArray):JSONObject {
        val key=hkdf(c0hash(outerSeed),outerSalt,outerInfo)
        var logical=data
        repeat(6){
            if(logical.size>=40){
                val nonce=logical.copyOfRange(0,24)
                val encrypted=logical.copyOfRange(24,logical.size)
                try{return parseObject(xdec(key,nonce,outerAad,encrypted))}
                catch(_:Exception){}
                // V3 outer is a stream envelope, not an authenticated
                // outer envelope. Inner sections still require valid AEAD.
                try {
                    val body=logical.copyOfRange(24,logical.size-16)
                    val v=parseObject(xor(body,v3,nonce))
                    if(v.optString("a")=="HCCFG")return v
                }catch(_:Exception){}
            }
            logical=try {
                val unicode=p.utf8(logical)
                if(unicode.any{it.code>255})return@repeat
                val nxt=ByteArray(unicode.length){unicode[it].code.toByte()}
                if(nxt.contentEquals(logical))return@repeat
                nxt
            }catch(_:Exception){return@repeat}
        }
        error("Unsupported HCCFG envelope")
    }
    private fun featureBytes(env:JSONObject):ByteArray {
        val f=env.getJSONArray("f")
        require(f.length()<=128 && (0 until f.length()).all { f.get(it) is String })
        return utf((0 until f.length()).joinToString(","){f.getString(it)})
    }
    private fun nBytes(env:JSONObject):ByteArray? {
        val obj=env.opt("n")
        if(obj==null||obj==JSONObject.NULL)return null
        require(obj !is Boolean)
        val n=obj.toString().toLongOrNull()?:error("Bad version n")
        require(n>=0 && n.toString()==obj.toString())
        return utf(n.toString())
    }
    private fun key(env:JSONObject):ByteArray=p.hex(env.getString("g")).also {
        require(it.size==32)
    }
    private fun derive(env:JSONObject,passwordBytes:ByteArray?,hwid:String?):Pair<ByteArray,ByteArray>{
        require(env.getString("a")=="HCCFG")
        val schema=env.getInt("b")
        require(schema in listOf(1,2,5,7))
        require(env.getString("c")==if(schema==1)"XCHACHA20P1305" else "s1")
        require(env.getString("d")==if(schema==1)"NATIVE-HKDF-SHA256" else "h1")
        val schedule=env.getString("e")
        require(schedule in listOf("n1","n2","n7","n8"))
        val hwidRequired=schedule=="n2"||schedule=="n8"
        val n7mode=schedule=="n7"||schedule=="n8"
        val features=featureBytes(env);val nb=nBytes(env);val vk=utf("1")
        val seedKey=key(env)
        val hw=if(hwidRequired){
            require(hwid!=null){"HWID_REQUIRED"}
            val value=hwid.trim().uppercase(java.util.Locale.ROOT)
            require(value.length==32 && value.all{it in "0123456789ABCDEFH"}){"Bad HWID"}
            utf(value)
        }else null
        val t=ByteArrayOutputStream().apply {
            write(utf("HCCFG"));write(zero);write(pkg);write(zero)
            write(vk);write(zero);write(features);write(zero)
            if(nb!=null){write(nb);write(zero)}
            if(hw!=null){write(utf("hwid"));write(zero);write(hw);write(zero)}
            write(seedKey)
        }.toByteArray()
        var ikm=if(n7mode)mac(n7,bytes(byteArrayOf(0xd3.toByte()),c0.copyOf(32),t))
            else c0hash(t)
        val protectionFlag=when(val flag=env.opt("h")) {
            null,JSONObject.NULL,false -> 0
            true -> 1
            is Number -> flag.toInt().also { require(it==0||it==1) }
            else -> error("Bad HCCFG protection flag")
        }
        val protectionAad=if(protectionFlag==1){
            require(passwordBytes!=null && passwordBytes.isNotEmpty()){"PASSWORD_REQUIRED"}
            val ops=env.getInt("l")
            val mem=env.getInt("m")
            require(ops in 1..16 && mem in (8*1024*1024)..(256*1024*1024) && mem%1024==0) {
                "Argon2 parameter limits exceeded"
            }
            require(env.getString("k") in listOf("ARGON2ID13","a1"))
            val params=Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withSalt(seedKey.copyOfRange(0,16)).withIterations(ops)
                .withMemoryAsKB(mem/1024).withParallelism(1)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13).build()
            val out=ByteArray(32)
            Argon2BytesGenerator().apply{init(params)}.generateBytes(passwordBytes,out)
            ikm=bytes(ikm,out);out.fill(0)
            utf("|1|ARGON2ID13|$ops|$mem")
        }else utf("|0")
        val info=ByteArrayOutputStream().apply{
            write(utf("app-config|$schedule|"));write(pkg)
            write(utf("|1|"));write(features)
            if(nb!=null){write(utf("|"));write(nb)}
            if(hw!=null){write(utf("|hwid|"));write(hw)}
        }.toByteArray()
        val skey=hkdf(ikm,seedKey,info)
        val aad=ByteArrayOutputStream().apply{
            write(utf("HCCFG|$schema|XCHACHA20P1305|NATIVE-HKDF-SHA256|$schedule|"))
            write(pkg);write(utf("|1|"));write(features);write(protectionAad)
            if(nb!=null){write(utf("|"));write(nb)}
        }.toByteArray()
        if(!hwidRequired)return skey to aad
        val slots=env.getJSONArray("o")
        require(slots.length() in 1..256)
        for(i in 0 until slots.length()){
            val sec=slots.optJSONObject(i)?:continue
            try{
                val sk=verifiedSlotDecrypt(skey,p.hex(sec.getString("a")),
                    bytes(aad,zero,utf("w")),p.hex(sec.getString("b")))
                if(sk.size==32)return sk to aad
            }catch(_:Exception){}
        }
        error("AUTH_FAILED")
    }
    /**
     * Android's BigInteger-based Poly1305 fallback had a slot-only parity
     * mismatch on API35, although the derived key and AAD matched the Python
     * reference. Verify the HWID slot via the vetted, already bundled BC
     * ChaCha20-Poly1305 implementation using the XChaCha20 subkey/nonce.
     * Never downgrade a failed authenticated slot to stream plaintext.
     */
    private fun verifiedSlotDecrypt(key:ByteArray,nonce:ByteArray,aad:ByteArray,
        ciphertextWithTag:ByteArray):ByteArray {
        require(key.size==32 && nonce.size==24 && ciphertextWithTag.size>=16 &&
            ciphertextWithTag.size<=p.MAX_INPUT)
        val sub=hchacha(key,nonce.copyOfRange(0,16))
        val nonce12=bytes(ByteArray(4),nonce.copyOfRange(16,24))
        try {
            val cipher=ChaCha20Poly1305()
            cipher.init(false,AEADParameters(KeyParameter(sub),128,nonce12,aad))
            val clear=ByteArray(cipher.getOutputSize(ciphertextWithTag.size))
            val produced=cipher.processBytes(ciphertextWithTag,0,
                ciphertextWithTag.size,clear,0)
            val completed=cipher.doFinal(clear,produced)
            val size=produced+completed
            if(size!=clear.size) {
                val result=clear.copyOf(size)
                clear.fill(0)
                return result
            }
            return clear
        } finally {
            sub.fill(0)
            nonce12.fill(0)
        }
    }

    private fun section(sec:JSONObject,key:ByteArray,aad:ByteArray):ByteArray {
        val label=sec.getString("a");require(label.isNotEmpty()&&label.length<=256)
        return xdec(key,p.hex(sec.getString("b")),
            bytes(aad,zero,utf(label)),p.hex(sec.getString("c")))
    }
    private fun sidecar(sec:JSONObject,key:ByteArray,aad:ByteArray):ByteArray? {
        val nested=sec.optJSONObject("d")?:return null
        val label=sec.getString("a")
        return xdec(key,p.hex(nested.getString("a")),
            bytes(aad,zero,utf(label),utf(":x")),p.hex(nested.getString("b")))
    }
    private fun hpr1(raw:ByteArray,key:ByteArray,aad:ByteArray,label:String,
        strictAuthentication:Boolean=false):ByteArray{
        if(raw.size<4 || !raw.copyOfRange(0,4).contentEquals(utf("HPR1")))return raw
        if(raw.size<44) {
            if(strictAuthentication)error("Truncated protected HPR1 envelope")
            return raw
        }
        val nonce=raw.copyOfRange(4,28);val body=raw.copyOfRange(28,raw.size)
        return try{xdec(key,nonce,bytes(aad,zero,utf("$label:r")),body)}
        catch(failure:Exception){
            // New protected imports match HTTPCUSTOM_AUTH.py: never downgrade
            // an invalid HPR1 tag into unverified stream plaintext.
            if(strictAuthentication)throw failure
            // Retain pre-existing legacy/unprotected behavior for parity.
            xor(body.copyOfRange(0,body.size-16),key,nonce)
        }
    }
    private class HPC1(data:ByteArray){
        val buf=ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
        fun bytes(count:Int):ByteArray{
            require(count>=0&&count<=buf.remaining())
            return ByteArray(count).also{buf.get(it)}
        }
        fun int():Int{require(buf.remaining()>=4);return buf.int}
        fun long():Long{require(buf.remaining()>=8);return buf.long}
        fun text():String{
            val n=int();require(n in 0..(1024*1024));return p.utf8(bytes(n))
        }
        fun parse(label:String):JSONObject{
            require(bytes(4).contentEquals(utf("HPC1")))
            require(int()==11)
            val name=text();val proto=text();val host=text();val port=int()
            val user=text();val pass=text();val payload=text();val opts=text()
            val flags=int();val updated=long();val mode=text()
            require(!buf.hasRemaining())
            val obj=JSONObject()
            obj.put("name",name);obj.put("protocol",proto);obj.put("host",host)
            obj.put("port",port);obj.put("username",user);obj.put("password",pass)
            obj.put("payload",payload)
            obj.put("options",if(opts.isBlank())JSONObject() else try{JSONObject(opts)}catch(_:Exception){opts})
            obj.put("flags",flags);obj.put("updated_at_ms",updated);obj.put("mode",mode)
            obj.put("label",label)
            return obj
        }
    }
    private fun sections(obj:Any?):List<JSONObject>{
        return when(obj){
            is JSONArray ->{
                require(obj.length()<=256)
                (0 until obj.length()).map{obj.getJSONObject(it)}
            }
            is JSONObject ->{
                val keys=p.keys(obj);require(keys.size<=256)
                keys.map{obj.getJSONObject(it)}
            }
            else->error("Invalid HCCFG sections")
        }
    }
    private fun normalizedProtections(pObj:JSONObject):JSONObject{
        val out=JSONObject()
        for(k in p.keys(pObj))out.put(protectionNames[k]?:k,pObj.get(k))
        return out
    }
    private fun decodeEnv(env:JSONObject,passwordBytes:ByteArray?,hwid:String?,
        strictAuthentication:Boolean=false,fullResult:Boolean=false):JSONObject {
        val (key,aad)=derive(env,passwordBytes,hwid)
        val main=env.getJSONObject("i")
        val raw=section(main,key,aad)
        val decoded=parseObject(raw)
        val configs=JSONArray();val others=JSONArray()
        for(sec in sections(env.opt("j")?:JSONArray())){
            val label=sec.getString("a")
            var plaintext=section(sec,key,aad)
            plaintext=hpr1(plaintext,key,aad,label,strictAuthentication)
            val side=sidecar(sec,key,aad)
            if(plaintext.size>=4 && plaintext.copyOfRange(0,4).contentEquals(utf("HPC1"))){
                val profile=HPC1(plaintext).parse(label)
                val clean=JSONObject()
                for(field in listOf("name","protocol","host","port","username","password","mode"))
                    clean.put(field,profile.get(field))
                val opts=profile.optJSONObject("options")
                if(opts!=null)for(k in p.keys(opts))clean.put(k,opts.get(k))
                if(profile.optString("payload").isNotEmpty())clean.put("payload",profile.getString("payload"))
                if(side!=null)try {clean.put("custom_payload_sidecar",p.utf8(side))}
                catch(_:Exception){clean.put("custom_payload_sidecar_hex",side.joinToString(""){"%02x".format(it.toInt() and 255)})}
                configs.put(if(fullResult)profile else clean)
            }else {
                val item=JSONObject().put("label",label)
                val text=try{p.utf8(plaintext)}catch(_:Exception){null}
                val content=if(text!=null && text.startsWith("{"))try{JSONObject(text)}catch(_:Exception){text}
                    else if(text!=null && text.startsWith("["))try{JSONArray(text)}catch(_:Exception){text}
                    else text?:JSONObject().put("hex",plaintext.joinToString(""){"%02x".format(it.toInt() and 255)})
                item.put("content",content);others.put(item)
            }
        }
        val n=env.opt("n")
        val appVer=try{
            val num=n.toString().toInt()
            schemaVersions[num]?.let{"$it ($num)"}?:"build-$num"
        }catch(_:Exception){"build-$n"}
        return JSONObject().apply {
            put("app_version",appVer);put("config",configs)
            put("protections",normalizedProtections(decoded.optJSONObject("g")?:JSONObject()))
            if(fullResult){
                val schedule=env.getString("e")
                put("requirements",JSONObject()
                    .put("password_required",passwordRequired(env))
                    .put("hwid_required",schedule=="n2"||schedule=="n8")
                    .put("hwid_slots",env.optJSONArray("o")?.length()?:0))
                put("main_config",decoded)
            }
            if(others.length()>0)put("other_sections",others)
        }
    }
    data class Requirements(
        val passwordRequired:Boolean,
        val hwidRequired:Boolean,
        val headerAuthenticated:Boolean,
        val schema:Int,
        val schedule:String,
    ) {
        val requiresCredentials:Boolean get()=passwordRequired||hwidRequired
    }

    private fun passwordRequired(env:JSONObject):Boolean=when(val flag=env.opt("h")){
        null,JSONObject.NULL,false->false
        true->true
        is Number->{
            val int=flag.toInt()
            require((int==0||int==1) && flag.toString()==int.toString())
            int==1
        }
        else->error("Invalid password flag")
    }

    /**
     * No KDF is executed during inspection. The stream-v3 outer header is
     * explicitly NOT authenticated; trust is only established after the
     * protected sections (and HPR1) authenticate with supplied credentials.
     */
    fun inspectRequirements(input:ByteArray):Requirements?=runCatching {
        p.bounded(input)
        val env=openOuter(input)
        if(env.optString("a")!="HCCFG")return@runCatching null
        val schema=env.getInt("b")
        require(schema in listOf(1,2,5,7))
        require(env.getString("c")==if(schema==1)"XCHACHA20P1305" else "s1")
        require(env.getString("d")==if(schema==1)"NATIVE-HKDF-SHA256" else "h1")
        val schedule=env.getString("e")
        require(schedule in listOf("n1","n2","n7","n8"))
        featureBytes(env);nBytes(env);key(env)
        val locked=passwordRequired(env)
        if(locked){
            require(env.getString("k") in listOf("ARGON2ID13","a1"))
            val ops=env.getInt("l");val mem=env.getInt("m")
            require(ops in 1..16 && mem in (8*1024*1024)..(256*1024*1024) &&
                mem%1024==0)
        }
        val hwidLocked=schedule=="n2"||schedule=="n8"
        if(hwidLocked)require(env.getJSONArray("o").length() in 1..256)
        // Current inspection can parse both outer forms; do not claim
        // authenticated-v1 unless its tag is independently verified.
        Requirements(locked,hwidLocked,outerHeaderAuthenticated(input),schema,schedule)
    }.getOrNull()

    private fun outerHeaderAuthenticated(input:ByteArray):Boolean {
        val key=hkdf(c0hash(outerSeed),outerSalt,outerInfo)
        var logical=input
        repeat(6){
            if(logical.size>=40) {
                try {
                    val plain=xdec(key,logical.copyOfRange(0,24),outerAad,
                        logical.copyOfRange(24,logical.size))
                    if(parseObject(plain).optString("a")=="HCCFG")return true
                }catch(_:Exception){}
            }
            logical=try {
                val str=p.utf8(logical)
                if(str.any{it.code>255})return false
                val next=ByteArray(str.length){str[it].code.toByte()}
                if(next.contentEquals(logical))return false
                next
            }catch(_:Exception){return false}
        }
        return false
    }

    /** Test-only stage report, never contains plaintext, keys or credentials. */
    internal fun syntheticTestStage(input:ByteArray,password:ByteArray?,hwid:String?):String {
        val env=try{openOuter(input)}catch(_:Exception){return "outer"}
        val (contentKey,aad)=try{derive(env,password,hwid)}
            catch(_:Exception){return "slot-derive"}
        val main=try{section(env.getJSONObject("i"),contentKey,aad)}
            catch(_:Exception){return "main-aead"}
        if(runCatching{parseObject(main)}.isFailure)return "main-json"
        val sections=try{sections(env.opt("j")?:JSONArray())}
            catch(_:Exception){return "profiles-list"}
        for(sec in sections) {
            val label=sec.optString("a")
            val raw=try{section(sec,contentKey,aad)}
                catch(_:Exception){return "profile-aead"}
            val plain=try{hpr1(raw,contentKey,aad,label,true)}
                catch(_:Exception){return "hpr1-aead"}
            if(plain.size>=4 && plain.copyOfRange(0,4).contentEquals(utf("HPC1"))) {
                try{HPC1(plain).parse(label)}catch(_:Exception){return "profile-hpc1"}
            }
        }
        return "complete"
    }

    /** Original S.4 password detector retained for existing security gates. */
    fun requiresExternalPassword(input:ByteArray):Boolean =
        inspectRequirements(input)?.passwordRequired==true

    private fun decodeBytes(input:ByteArray,passwordBytes:ByteArray?,hwid:String?,
        strictAuthentication:Boolean=false,fullResult:Boolean=false):String?=
        p.safeDecode {
            p.bounded(input)
            p.prettyJson(decodeEnv(openOuter(input),passwordBytes,hwid,
                strictAuthentication,fullResult))+"\n"
        }

    /** Legacy source compatibility; any temporary UTF-8 copy is zeroed. */
    fun decode(input:ByteArray,password:String?=null,hwid:String?=null):String? {
        val bytes=password?.toByteArray(Charsets.UTF_8)
        return try { decodeBytes(input,bytes,hwid) }
        finally { bytes?.fill(0) }
    }

    /** Password bytes are owned and immediately cleared by the vault callback. */
    fun decodeWithUserPassword(input:ByteArray,password:ByteArray):String? {
        if(password.isEmpty() || password.size>4096)return null
        return decodeBytes(input,password,null,strictAuthentication=true,fullResult=true)
    }

    /**
     * Protected HCCFG only. Password bytes and HWID are caller-supplied and
     * never taken from Android identifiers or embedded into result JSON.
     * Password and HWID must be entered together for n8 + h=1.
     */
    fun decodeWithCredentials(input:ByteArray,password:ByteArray?,hwid:String?):String? {
        val needs=inspectRequirements(input)?:return null
        if(!needs.requiresCredentials)return null
        if(needs.passwordRequired && (password==null || password.isEmpty() ||
            password.size>4096))return null
        if(needs.hwidRequired && hwid.isNullOrBlank())return null
        return decodeBytes(input,if(needs.passwordRequired)password else null,
            if(needs.hwidRequired)hwid else null,
            strictAuthentication=true,fullResult=true)
    }
}
