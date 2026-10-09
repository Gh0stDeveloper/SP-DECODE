package com.ghostdeveloper.spdecode

import android.content.Context
import androidx.datastore.core.IOException
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.map

private val Context.historyPreferencesStore by preferencesDataStore("spdecode-history-settings")

data class SavedHistoryPreferences(val retentionDays:Int=0,val selectedId:String?=null)

/**
 * DataStore contains ONLY non-secret settings / an optional opaque UUID.
 * Raw texts, decrypted fields, favorites and filenames remain inside
 * the no-backup AndroidKeyStore-encrypted history store.
 */
class HistoryPreferences(context:Context) {
    private val store=context.applicationContext.historyPreferencesStore
    private val retentionKey=intPreferencesKey("retention_days")
    private val currentKey=stringPreferencesKey("current_result_id")

    val values:Flow<SavedHistoryPreferences> = store.data
        .catch { if(it is IOException) emit(androidx.datastore.preferences.core.emptyPreferences())
                 else throw it }
        .map { prefs ->
            SavedHistoryPreferences(
                retentionDays=prefs[retentionKey].takeIf { it in choices }?:0,
                selectedId=prefs[currentKey],
            )
        }

    suspend fun setRetentionDays(days:Int) {
        require(days in choices)
        store.edit { it[retentionKey]=days }
    }
    suspend fun setSelectedId(id:String?) {
        store.edit { values ->
            if(id==null) values.remove(currentKey)
            else {
                require(runCatching { java.util.UUID.fromString(id).toString()==id }
                    .getOrDefault(false))
                values[currentKey]=id
            }
        }
    }
    companion object {
        val choices=setOf(0,7,30,90,365)
    }
}
