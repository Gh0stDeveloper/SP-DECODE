package com.ghostdeveloper.spdecode

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Synthetic test entries only: no genuine profiles or credentials. */
@RunWith(AndroidJUnit4::class)
class HistoryManagementInstrumentedTest {
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun filtersSearchMetadataOnlyAndSortDeterministically() {
        val old=DecodeView("one.ehi","ehi","Password: HIDDEN_EXAMPLE",5,
            savedAtMillis=1000L)
        val recent=DecodeView("two.ht","ht","Server: DEMO",6,
            savedAtMillis=2000L,favorite=true)
        val named=DecodeView("alpha.ehi","ehi","token: ANOTHER_SECRET",5,
            savedAtMillis=3000L,favorite=true)
        val entries=listOf(old,recent,named)
        assertTrue(HistorySearch.apply(entries,HistoryFilter(query="HIDDEN_EXAMPLE")).isEmpty())
        assertEquals(listOf("alpha.ehi","one.ehi"),
            HistorySearch.apply(entries,HistoryFilter(extension="ehi"))
                .map{it.filename})
        assertEquals(listOf("two.ht","alpha.ehi"),
            HistorySearch.apply(entries,HistoryFilter(favoritesOnly=true,
                sort=HistorySort.OLDEST)).map{it.filename})
        assertEquals("alpha.ehi", HistorySearch.apply(entries,
            HistoryFilter(sort=HistorySort.NAME)).first().filename)
    }

    @Test fun favoritePersistsEncryptedAndRetentionExcludesFavorites() {
        val storage=SecureDecodeHistory(ctx)
        val oldMillis=System.currentTimeMillis()-40L*86_400_000L
        val old=DecodeView("old.ehi","ehi","password: private-demo",20,
            savedAtMillis=oldMillis)
        val favored=DecodeView("fav.ht","ht","password: hidden-demo",24,
            savedAtMillis=oldMillis)
        val recent=DecodeView("new.ehi","ehi","localhost",4)
        try {
            listOf(old,favored,recent).forEach(storage::save)
            val starred=storage.setFavorite(favored.id,true)
            assertTrue(starred.favorite)
            val restored=SecureDecodeHistory(ctx).load().single{it.id==favored.id}
            assertTrue(restored.favorite)
            assertEquals(favored.rawText,restored.rawText)
            val deleted=storage.pruneOlderThan(
                System.currentTimeMillis()-30L*86_400_000L)
            assertTrue(old.id in deleted)
            assertFalse(favored.id in deleted)
            assertFalse(recent.id in deleted)
            val survivors=storage.load().map{it.id}.toSet()
            assertFalse(old.id in survivors)
            assertTrue(favored.id in survivors)
            assertTrue(recent.id in survivors)
            assertFalse(java.io.File(ctx.noBackupFilesDir,
                "decode-history/${favored.id}.bin").readText()
                .contains("hidden-demo"))
        } finally {
            storage.delete(setOf(old.id,favored.id,recent.id))
        }
    }

    @Test fun datastoreRetainsOnlyNonsecretSettings() = runBlocking {
        val prefs=HistoryPreferences(ctx)
        val before=prefs.values.first()
        val marker=java.util.UUID.randomUUID().toString()
        try {
            prefs.setRetentionDays(90)
            prefs.setSelectedId(marker)
            val restored=HistoryPreferences(ctx).values.first()
            assertEquals(90,restored.retentionDays)
            assertEquals(marker,restored.selectedId)
            try { prefs.setRetentionDays(-1);fail("invalid retention") }
            catch(_:IllegalArgumentException) {}
        } finally {
            prefs.setRetentionDays(before.retentionDays)
            prefs.setSelectedId(before.selectedId)
        }
    }

    @Test fun thirtyFileBatchSkipsFailuresButDoesNotDropLaterEntries() = runBlocking {
        val seen=mutableListOf<Int>()
        val report=BatchImportQueue.process((1..30).toList()){item,index,total->
            assertEquals(30,total)
            assertEquals(item,index)
            if(item%3==0)throw IllegalArgumentException("bad file")
            seen.add(item)
        }
        assertEquals(30,report.processed)
        assertEquals(20,report.successes)
        assertEquals(10,report.failures)
        assertTrue(29 in seen)
        assertTrue(HistorySearch.apply(emptyList(),HistoryFilter()).isEmpty())
        try {
            BatchImportQueue.process((1..31).toList()){_,_,_->}
            fail("must reject over-limit batch")
        } catch(_:IllegalArgumentException) {}
    }

    @Test fun batchPropagatesCancellationImmediately() = runBlocking {
        var attempts=0
        try {
            BatchImportQueue.process((1..30).toList()){item,_,_->
                attempts++
                if(item==4)throw CancellationException("user canceled")
            }
            fail("Cancellation must propagate")
        }catch(_:CancellationException){
            assertEquals(4,attempts)
        }
    }
}
