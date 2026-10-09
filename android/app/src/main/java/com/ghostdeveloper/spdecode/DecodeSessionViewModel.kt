package com.ghostdeveloper.spdecode

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel

/** In-memory only. A configuration change (language/rotation) must not lose
 * a currently open profile, but no raw profile is saved in a Bundle or disk.
 */
class DecodeSessionViewModel:ViewModel(){
    val recent=mutableStateListOf<DecodeView>()
    var current by mutableStateOf<DecodeView?>(null)
    var tab by mutableIntStateOf(0)
    var reveal by mutableStateOf(false)
}
