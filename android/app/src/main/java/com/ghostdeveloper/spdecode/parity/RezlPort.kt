package com.ghostdeveloper.spdecode.parity
/** .rezl: original shared rez.js prints .rez, no format mixing. */
object RezlPort {fun decode(input:ByteArray)=LegacyTeaSourcePort.renderRez(input)}
