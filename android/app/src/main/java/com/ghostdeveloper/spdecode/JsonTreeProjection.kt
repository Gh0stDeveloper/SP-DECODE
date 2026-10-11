package com.ghostdeveloper.spdecode

import com.google.gson.JsonElement

/**
 * Read-only, bounded projection of decoded JSON for the Compose result viewer.
 *
 * Never rewrites the stored decoded result or JSON/clipboard exports. Large
 * containers are paged at every level, and only open branches are traversed.
 * Paths use sibling indices rather than field names, so duplicate labels,
 * unusual Unicode, dots and slash characters cannot collide.
 */
internal object JsonTreeProjection {
    const val PAGE_SIZE = 80
    const val MAX_VISIBLE_ROWS = 5000
    private const val MAX_TREE_DEPTH = 64

    enum class Kind { NODE, VALUE, END, MORE, LIMIT }

    data class Row(
        val path: String,
        val depth: Int,
        val kind: Kind,
        val key: String? = null,
        val value: JsonElement? = null,
        val bracket: Char = ' ',
        val expanded: Boolean = false,
        val total: Int = 0,
        val remaining: Int = 0,
        val comma: Boolean = false,
    )

    /** A small first nested object opens by default, preserving useful context. */
    fun defaultExpanded(depth: Int, children: Int): Boolean =
        depth == 0 || (depth == 1 && children <= 12)

    fun project(
        root: JsonElement,
        expandedOverrides: Map<String, Boolean> = emptyMap(),
        pageLimits: Map<String, Int> = emptyMap(),
    ): List<Row> {
        val result = ArrayList<Row>()
        var stopped = false

        fun append(row: Row): Boolean {
            if (stopped) return false
            if (result.size >= MAX_VISIBLE_ROWS - 1) {
                result.add(Row("limit", 0, Kind.LIMIT))
                stopped = true
                return false
            }
            result.add(row)
            return true
        }

        fun visit(element: JsonElement, key: String?, path: String,
                  depth: Int, comma: Boolean) {
            if (stopped) return
            val obj = if (element.isJsonObject) element.asJsonObject else null
            val arr = if (element.isJsonArray) element.asJsonArray else null
            if (obj == null && arr == null) {
                append(Row(path, depth, Kind.VALUE, key, element, comma = comma))
                return
            }

            val total = obj?.size() ?: arr!!.size()
            val opening = if (obj != null) '{' else '['
            val closing = if (obj != null) '}' else ']'
            val isExpanded = (expandedOverrides[path] ?: defaultExpanded(depth, total)) &&
                depth < MAX_TREE_DEPTH
            if (!append(Row(path, depth, Kind.NODE, key, bracket = opening,
                    expanded = isExpanded, total = total, comma = comma))) return
            if (!isExpanded) return

            val count = (pageLimits[path] ?: PAGE_SIZE).coerceIn(1, total.coerceAtLeast(1))
            if (obj != null) {
                val iterator = obj.entrySet().iterator()
                var index = 0
                while (index < count && iterator.hasNext() && !stopped) {
                    val entry = iterator.next()
                    visit(entry.value, entry.key, "$path/$index", depth + 1, index < total - 1)
                    index++
                }
            } else {
                for (index in 0 until count) {
                    if (stopped) break
                    visit(arr!![index], null, "$path/$index", depth + 1, index < total - 1)
                }
            }
            if (count < total && !stopped) {
                append(Row(path, depth + 1, Kind.MORE, remaining = total - count))
            }
            if (!stopped) append(Row("$path/end", depth, Kind.END,
                bracket = closing, comma = comma))
        }

        visit(root, null, "root", 0, false)
        return result
    }
}
