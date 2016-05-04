package com.tma.afl3;

import java.math.BigInteger;

public class PrivateKey {
    private BigInteger n;
    private BigInteger d;

    public PrivateKey(BigInteger n, BigInteger d) {
        this.n = n;
        this.d = d;
    }

    public BigInteger getN() {
        return n;
    }

    public BigInteger getD() {
        return d;
    }
}
