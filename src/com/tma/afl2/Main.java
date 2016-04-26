package com.tma.afl2;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            RSA rsa = new RSA();
            rsa.keyGen(2048);

            while (true) {
                System.out.println("Write a string to be signed/verified, or press enter to measure hash/signature times");
                String str = scanner.nextLine();
                if (str.equals(""))
                    break;

                byte[] message = str.getBytes("UTF-8");

                byte[] signature = rsa.sign(message);
                System.out.printf("%s verified: %s\n", str, rsa.verify(message, signature));
                System.out.printf("%sabc verified: %s\n", str, rsa.verify((str + "abc").getBytes("UTF-8"), signature));
                System.out.println();
            }

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] message = new byte[10 * 1024];
            for (int i = 0; i < message.length; i++)
                message[i] = (byte) i;

            long start = System.nanoTime();
            final int hashTries = 10000;
            for (int i = 0; i < hashTries; i++) {
                sha256.digest(message);
            }
            long elapsed = System.nanoTime() - start;

            // Gives approximately 1500 megabits/second
            double hashSpeed = (hashTries * message.length / 1024.0 / 1024.0 * 8) / (elapsed / 1000000000d);
            System.out.printf("Hash speed: %s megabits/second\n", hashSpeed);

            rsa = new RSA();
            rsa.keyGen(2000);

            final int signTimes = 60;

            byte[] messageHash = sha256.digest(message);
            start = System.nanoTime();
            for (int i = 0; i < signTimes; i++)
                rsa.sign(messageHash);
            elapsed = System.nanoTime() - start;

            // Gives about 70 signatures/second,
            double signaturesPerSecond = signTimes / (elapsed / 1000000000d);
            // So the speed for RSA is around 2000 * 70
            // = ~140 kbit/second, ~10000 times slower than the hash version
            double rsaSpeed = signaturesPerSecond * (2000 / 1024.0 / 1024.0);
            System.out.printf("Signature speed: %s megabits/second\n", rsaSpeed);

            double speedup = hashSpeed / rsaSpeed;
            System.out.printf("Hash version is %s times faster than RSA version\n", speedup);
            System.out.println();
        }
    }
}
