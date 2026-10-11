package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class DevicePrivateCredentialVaultInstrumentedTest {
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun encryptedRecordsCanBeListedUsedAndDeleted() {
        val vault=DevicePrivateCredentialVault(ctx)
        val input="S4_SAMPLE_VALUE_NOT_A_REAL_CREDENTIAL".toByteArray()
        val expected=input.copyOf()
        val record=vault.provision("Temporary test entry",input)
        input.fill(0)
        try {
            val file=File(ctx.noBackupFilesDir,"private-credentials/${record.id}.s4k")
            assertTrue(file.isFile)
            assertEquals("S4K1",file.readBytes().copyOfRange(0,4).toString(Charsets.US_ASCII))
            assertFalse(file.readBytes().toString(Charsets.ISO_8859_1)
                .contains("S4_SAMPLE_VALUE_NOT_A_REAL_CREDENTIAL"))
            assertTrue(vault.inventory().entries.any{it.id==record.id})
            val escaped=vault.use(record.id){bytes->
                assertArrayEquals(expected,bytes)
                bytes
            }
            assertTrue(escaped.all{it==0.toByte()})
        }finally{
            vault.delete(record.id)
            expected.fill(0)
        }
        assertFalse(vault.inventory().entries.any{it.id==record.id})
    }

    @Test fun modifiedOrRenamedRecordsAreRejected() {
        val vault=DevicePrivateCredentialVault(ctx)
        val record=vault.provision("Integrity example",byteArrayOf(10,20,30))
        val file=File(ctx.noBackupFilesDir,"private-credentials/${record.id}.s4k")
        val alias=UUID.randomUUID().toString()
        val other=File(file.parentFile,"$alias.s4k")
        val original=file.readBytes()
        try {
            other.writeBytes(original)
            assertThrows(Exception::class.java){vault.use(alias){}}
            val changed=original.copyOf()
            changed[changed.lastIndex]=(changed.last().toInt() xor 1).toByte()
            file.writeBytes(changed)
            assertThrows(Exception::class.java){vault.use(record.id){}}
            assertTrue(vault.inventory().unreadable>0)
        }finally{
            vault.delete(alias)
            vault.delete(record.id)
        }
    }

    @Test fun invalidLengthsAndRecordNamesFailClosed() {
        val vault=DevicePrivateCredentialVault(ctx)
        assertThrows(IllegalArgumentException::class.java){
            vault.provision("Example",ByteArray(4097))
        }
        assertThrows(IllegalArgumentException::class.java){
            vault.provision("bad\nlabel",byteArrayOf(1))
        }
        assertThrows(IllegalArgumentException::class.java){
            vault.use("not-a-valid-id"){}
        }
    }
}
