package com.ghostdeveloper.spdecode.parity
import android.content.Context
/** NPVT uses identical original NPVTUNNEL white-box core. */
object NpvtPort {fun decode(context:Context,input:ByteArray)=NpvWhiteboxReferencePort.decode(context,input)}
