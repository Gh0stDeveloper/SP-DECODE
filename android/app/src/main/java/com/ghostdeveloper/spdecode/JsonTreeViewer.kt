package com.ghostdeveloper.spdecode

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.gson.JsonElement
import com.google.gson.JsonPrimitive
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// Syntax colors apply ONLY to JSON tokens. No app theme, surfaces, buttons,
// header, settings, copy/export actions or navigation colors are modified.
private val JsonKey = Color(0xFF7CB7F9)
private val JsonString = Color(0xFF98D9A0)
private val JsonNumber = Color(0xFFE8B66D)
private val JsonBoolean = Color(0xFFC9A0F3)
private val JsonNull = Color(0xFFE7A5B4)
private val JsonPunctuation = Color(0xFFF7F7F7)
private val JsonSecondary = Color(0xFFABABAB)

private const val INITIAL_STRING_CHARS = 512
private const val STRING_STEP = 1024

/**
 * Only the result preview changes: lazy, expandable, paginated syntax-highlighted
 * JSON with parsing off the UI thread. The raw data, encrypted history, native
 * decoders, copy and export paths are completely separate.
 */
@Composable
internal fun JsonTreeViewer(
    raw: String,
    suffix: String,
    maskCredentials: Boolean,
    identity: String,
) {
    val document by produceState<JsonElement?>(
        initialValue = null, raw, suffix, maskCredentials, identity
    ) {
        value = withContext(Dispatchers.Default) {
            ResultJsonDisplay.element(raw, suffix, maskCredentials)
        }
    }

    val expanded = remember(identity, maskCredentials) { mutableStateMapOf<String, Boolean>() }
    val pageLimits = remember(identity, maskCredentials) { mutableStateMapOf<String, Int>() }
    val stringLimits = remember(identity, maskCredentials) { mutableStateMapOf<String, Int>() }
    val root = document

    if (root == null) {
        Text(stringResource(R.string.json_viewer_loading),
            color = JsonSecondary, fontSize = 13.sp,
            style = TextStyle(textDirection = TextDirection.Ltr))
        return
    }

    val rows by remember(root, identity, maskCredentials) {
        derivedStateOf { JsonTreeProjection.project(root, expanded, pageLimits) }
    }
    LazyColumn(
        modifier = Modifier.fillMaxWidth().heightIn(max = 480.dp),
        contentPadding = PaddingValues(vertical = 2.dp),
    ) {
        items(rows, key = { "${it.path}:${it.kind}" }, contentType = { it.kind }) { row ->
            val indent = (row.depth.coerceAtMost(32) * 12).dp
            when (row.kind) {
                JsonTreeProjection.Kind.NODE -> {
                    val canExpand = row.depth < 64
                    Row(
                        modifier = Modifier.fillMaxWidth().then(
                            if (canExpand) Modifier.clickable {
                                expanded[row.path] = !row.expanded
                            } else Modifier
                        ).padding(start = indent, top = 2.dp, bottom = 2.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        if (canExpand) {
                            androidx.compose.material3.Icon(
                                if (row.expanded) Icons.Outlined.ExpandMore
                                else Icons.Outlined.ChevronRight,
                                contentDescription = stringResource(
                                    if (row.expanded) R.string.json_collapse else R.string.json_expand),
                                tint = JsonSecondary,
                                modifier = Modifier.size(16.dp)
                            )
                        } else Spacer(Modifier.width(16.dp))
                        Text(
                            jsonLine(row),
                            modifier = Modifier.weight(1f),
                            fontSize = 13.sp, lineHeight = 19.sp,
                            style = TextStyle(textDirection = TextDirection.Ltr)
                        )
                    }
                }
                JsonTreeProjection.Kind.VALUE -> {
                    val value = row.value
                    val length = if (value != null && value.isJsonPrimitive &&
                        value.asJsonPrimitive.isString) value.asString.length else 0
                    val limit = stringLimits[row.path] ?: INITIAL_STRING_CHARS
                    Column(modifier = Modifier.fillMaxWidth()
                        .padding(start = indent + 16.dp, top = 2.dp, bottom = 2.dp)) {
                        SelectionContainer {
                            Text(jsonLine(row, limit), fontSize = 13.sp, lineHeight = 19.sp,
                                style = TextStyle(textDirection = TextDirection.Ltr))
                        }
                        if (length > limit) {
                            TextButton(
                                onClick = {
                                    stringLimits[row.path] =
                                        (limit + STRING_STEP).coerceAtMost(length)
                                },
                                contentPadding = PaddingValues(0.dp)
                            ) {
                                Text(stringResource(R.string.json_more_chars,
                                    (length - limit).coerceAtMost(STRING_STEP)),
                                    color = JsonSecondary, fontSize = 12.sp)
                            }
                        }
                    }
                }
                JsonTreeProjection.Kind.END -> {
                    Text(jsonLine(row), modifier = Modifier.fillMaxWidth()
                        .padding(start = indent + 16.dp, top = 2.dp, bottom = 2.dp),
                        fontSize = 13.sp, lineHeight = 19.sp,
                        style = TextStyle(textDirection = TextDirection.Ltr))
                }
                JsonTreeProjection.Kind.MORE -> {
                    TextButton(
                        modifier = Modifier.padding(start = indent + 16.dp),
                        onClick = {
                            val current = pageLimits[row.path] ?: JsonTreeProjection.PAGE_SIZE
                            pageLimits[row.path] = current + JsonTreeProjection.PAGE_SIZE
                        },
                        contentPadding = PaddingValues(0.dp),
                    ) {
                        Text(stringResource(R.string.json_more_items,
                            row.remaining.coerceAtMost(JsonTreeProjection.PAGE_SIZE)),
                            color = JsonSecondary, fontSize = 12.sp)
                    }
                }
                JsonTreeProjection.Kind.LIMIT -> {
                    Text(stringResource(R.string.json_visible_limit),color = JsonSecondary,
                        fontSize = 12.sp)
                }
            }
        }
    }
}

/** AnnotatedString gives semantic token colors without changing the Android theme. */
private fun jsonLine(row: JsonTreeProjection.Row, stringChars: Int = INITIAL_STRING_CHARS) =
    buildAnnotatedString {
        row.key?.let { name ->
            withStyle(SpanStyle(color = JsonKey)) {
                append(JsonPrimitive(name).toString())
            }
            withStyle(SpanStyle(color = JsonPunctuation)) { append(": ") }
        }
        when (row.kind) {
            JsonTreeProjection.Kind.NODE -> {
                withStyle(SpanStyle(color = JsonPunctuation)) {
                    append(row.bracket)
                    if (!row.expanded) {
                        append(" … ")
                        append(if (row.bracket == '{') '}' else ']')
                    }
                    if (!row.expanded && row.comma) append(',')
                }
                if (!row.expanded) withStyle(SpanStyle(color = JsonSecondary)) {
                    append("  // ").append(row.total.toString())
                }
            }
            JsonTreeProjection.Kind.END -> {
                withStyle(SpanStyle(color = JsonPunctuation)) {
                    append(row.bracket)
                    if (row.comma) append(',')
                }
            }
            JsonTreeProjection.Kind.VALUE -> {
                val value = row.value
                when {
                    value == null || value.isJsonNull ->
                        withStyle(SpanStyle(color = JsonNull)) { append("null") }
                    value.isJsonPrimitive && value.asJsonPrimitive.isString -> {
                        val original = value.asString
                        val shortened = original.length > stringChars
                        val text = original.take(stringChars)
                        withStyle(SpanStyle(color = JsonString)) {
                            val quoted = JsonPrimitive(text).toString()
                            if (shortened) {
                                append(quoted.dropLast(1))
                                append("…\"")
                            } else append(quoted)
                        }
                    }
                    value.isJsonPrimitive && value.asJsonPrimitive.isBoolean ->
                        withStyle(SpanStyle(color = JsonBoolean)) { append(value.toString()) }
                    else -> withStyle(SpanStyle(color = JsonNumber)) { append(value.toString()) }
                }
                if (row.comma) withStyle(SpanStyle(color = JsonPunctuation)) { append(',') }
            }
            else -> Unit
        }
    }
