package com.ghostdeveloper.spdecode.parity

import org.bouncycastle.asn1.sec.SECNamedCurves
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.crypto.params.ECPublicKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import java.math.BigInteger

/** PyCryptodome DSS binary P-256 ECDSA signature verification parity. */
internal object NpvsSignature {
    fun verify(file:ByteArray, publicKey:ByteArray) {
        val p=NpvsPrimitives
        require(file.size>=64 && publicKey.size==33)
        val curve=SECNamedCurves.getByName("secp256r1")
            ?: throw IllegalArgumentException("P-256 not available")
        val point=curve.curve.decodePoint(publicKey)
        require(!point.isInfinity && point.isValid)
        val key=ECPublicKeyParameters(point,
            ECDomainParameters(curve.curve,curve.g,curve.n,curve.h))
        val sig=p.read(file,file.size-64,file.size)
        val r=BigInteger(1,p.read(sig,0,32))
        val s=BigInteger(1,p.read(sig,32,64))
        val verifier=ECDSASigner()
        verifier.init(false,key)
        require(verifier.verifySignature(p.sha(p.read(file,0,file.size-64)),r,s))
    }
}
