package com.tma.afl3;

import java.io.Serializable;
import java.math.BigInteger;

public class PublicKey implements Serializable{
    private BigInteger n;
    private BigInteger e;

    public PublicKey(BigInteger n, BigInteger e) {
        this.n = n;
        this.e = e;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getE() {
        return e;
    }
}
