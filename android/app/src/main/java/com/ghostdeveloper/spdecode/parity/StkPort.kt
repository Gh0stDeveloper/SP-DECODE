package com.ghostdeveloper.spdecode.parity
/** .stk: source's own TEA key and field ordering, not Rez key. */
object StkPort {fun decode(input:ByteArray)=LegacyTeaSourcePort.renderStk(input)}
