package com.tma.afl1;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class RSA {
    private PrivateKey sk;
    private PublicKey pk;

    public void keyGen(int length) {
        int primeLength = (int)Math.ceil(length / 2.0);

        BigInteger e = new BigInteger("3");
        Random random = new SecureRandom();
        BigInteger p, q, n;
        do {
            p = generatePrime(primeLength, e, random);
            q = generatePrime(primeLength, e, random);

            n = p.multiply(q);
        } while (n.bitLength() == length);

        PublicKey pk = new PublicKey(n, e);

        BigInteger p1q1 = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger d = e.modInverse(p1q1);

        assert d.multiply(e).mod(p1q1).equals(BigInteger.ONE);

        PrivateKey sk = new PrivateKey(n, d);

        this.sk = sk;
        this.pk = pk;
    }

    private BigInteger generatePrime(int primeLength, BigInteger e, Random random) {
        BigInteger p;
        do {
            p = BigInteger.probablePrime(primeLength, random);
        } while (!p.subtract(BigInteger.ONE).gcd(e).equals(BigInteger.ONE));
        return p;
    }

    public byte[] encrypt(String value) throws UnsupportedEncodingException {
        byte[] bytes = value.getBytes("UTF-8");
        BigInteger asNumber = new BigInteger(1, bytes);

        assert asNumber.bitLength() <= pk.getN().bitLength();

        BigInteger encrypted = asNumber.modPow(pk.getE(), pk.getN());
        return encrypted.toByteArray();
    }

    public String decrypt(byte[] encrypted) throws UnsupportedEncodingException {
        BigInteger asNumber = new BigInteger(encrypted);
        BigInteger result = asNumber.modPow(sk.getD(), sk.getN());
        byte[] bytes = result.toByteArray();
        return new String(bytes, "UTF-8");
    }
}

