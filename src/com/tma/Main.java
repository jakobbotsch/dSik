package com.tma;

import com.tma.afl1.RSA;

import java.io.UnsupportedEncodingException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws UnsupportedEncodingException {
        RSA rsa = new RSA();
        rsa.keyGen(2048);

        Scanner scanner = new Scanner(System.in);
        while (true) {
            String str = scanner.nextLine();
            byte[] encrypted = rsa.encrypt(str);
            String decrypted = rsa.decrypt(encrypted);

            System.out.printf("%s encrypted -> decrypted gives %s\n", str, decrypted);
        }
    }
}
