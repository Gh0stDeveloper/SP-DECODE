package com.ghostdeveloper.spdecode

import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.parity.AndroidOfflineDecoderRouter
import com.ghostdeveloper.spdecode.parity.EhiPort
import com.ghostdeveloper.spdecode.parity.SipPort
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/** The bot-produced standard-IV .ehi is tested byte-for-byte on Android. */
@RunWith(AndroidJUnit4::class)
class EhiStandardAndCompatibilityInstrumentedTest {
    private val inst get() = InstrumentationRegistry.getInstrumentation()
    private fun fixture(name: String) =
        inst.context.assets.open("parity/$"+"name").use { it.readBytes() }

    @Test fun standardArgon2idXChaCha20MatchesOriginalBotText() {
        val sample=fixture("ehi-standard-id.ehi")
        val expected=fixture("ehi-standard-id.txt")
        assertArrayEquals(expected,EhiPort.decode(sample)?.toByteArray(Charsets.UTF_8))
        assertArrayEquals(expected,AndroidOfflineDecoderRouter.decode(
            inst.targetContext,"profile.EHI",sample)?.toByteArray(Charsets.UTF_8))
    }

    @Test fun standardEhiWithTamperedEnvelopeNeverRendersSuccessfulProfile() {
        val sample=fixture("ehi-standard-id.ehi").clone()
        sample[sample.lastIndex-20]=(sample[sample.lastIndex-20].toInt() xor 0x40).toByte()
        assertNull(EhiPort.decode(sample))
    }

    @Test fun socksIpUnsupportedInnerVersionIsNotMisreportedAsSuccess() {
        val key=byteArrayOf(0x19,0x2e,0x04,0x08,0x08,0x04,0x04,0x09,0x05,0x59,
            0x29,0x59,0x38,0x5f,0x54,0x17)
        val encrypt=Cipher.getInstance("AES/ECB/PKCS5Padding")
        encrypt.init(Cipher.ENCRYPT_MODE,SecretKeySpec(key,"AES"))
        val encoded=Base64.encodeToString(
            encrypt.doFinal("VER7synthetic-profile".toByteArray(Charsets.US_ASCII)),
            Base64.NO_WRAP,
        ).toByteArray(Charsets.US_ASCII)
        assertNull(SipPort.decode(encoded))
        assertNull(AndroidOfflineDecoderRouter.decode(inst.targetContext,"sample.sip",encoded))
    }
}
