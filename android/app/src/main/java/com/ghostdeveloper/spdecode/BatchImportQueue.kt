package com.ghostdeveloper.spdecode

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.ensureActive
import kotlin.coroutines.coroutineContext

data class BatchImportReport(val successes:Int,val failures:Int) {
    val processed:Int get()=successes+failures
}

/** Sequential, bounded and cancellable. Failed files never abort the next file. */
object BatchImportQueue {
    const val MAX_FILES=30

    suspend fun <T> process(
        inputs:List<T>,
        action:suspend (value:T, index:Int, total:Int)->Unit,
    ):BatchImportReport {
        require(inputs.size<=MAX_FILES) { "Batch exceeds $MAX_FILES entries" }
        var passed=0
        var failed=0
        inputs.forEachIndexed { index, element ->
            coroutineContext.ensureActive()
            try {
                action(element,index+1,inputs.size)
                passed++
            }catch(cancelled:CancellationException) {
                throw cancelled
            }catch(_:Exception) {
                failed++
            }
        }
        return BatchImportReport(passed,failed)
    }
}
