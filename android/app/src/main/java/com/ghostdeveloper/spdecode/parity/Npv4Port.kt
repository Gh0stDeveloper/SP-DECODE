package com.ghostdeveloper.spdecode.parity
import android.content.Context
/** NPV4 uses identical original NPVTUNNEL white-box core. */
object Npv4Port {fun decode(context:Context,input:ByteArray)=NpvWhiteboxReferencePort.decode(context,input)}
