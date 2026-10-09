package com.ghostdeveloper.spdecode

import java.util.Locale

enum class HistorySort { NEWEST, OLDEST, NAME }

/** Search is deliberately metadata-only; never indexes decoded secrets. */
data class HistoryFilter(
    val query:String="",
    val extension:String?=null,
    val favoritesOnly:Boolean=false,
    val sort:HistorySort=HistorySort.NEWEST,
)

object HistorySearch {
    fun apply(items:List<DecodeView>,filter:HistoryFilter):List<DecodeView> {
        val q=filter.query.trim().lowercase(Locale.ROOT)
        val candidates=items.filter { entry ->
            (!filter.favoritesOnly || entry.favorite) &&
            (filter.extension==null || entry.extension.equals(filter.extension,true)) &&
            (q.isEmpty() ||
                entry.filename.lowercase(Locale.ROOT).contains(q) ||
                entry.extension.lowercase(Locale.ROOT).contains(q))
        }
        return when(filter.sort) {
            HistorySort.NEWEST->candidates.sortedWith(
                compareByDescending<DecodeView>{it.savedAtMillis}.thenBy{it.id})
            HistorySort.OLDEST->candidates.sortedWith(
                compareBy<DecodeView>{it.savedAtMillis}.thenBy{it.id})
            HistorySort.NAME->candidates.sortedWith(
                compareBy<DecodeView>{it.filename.lowercase(Locale.ROOT)}
                    .thenByDescending{it.savedAtMillis}.thenBy{it.id})
        }
    }
}
