package com.tma.afl4;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class Main {
    private static BigInteger p = new BigInteger("20756671680494528704396668367537632032160349980440698650786136551723850647769109279339848508870782502405405450233448746169592666050609746349475000592169043603913902380697512446424711876078978014475646427308067743532284974951683151446662464524010079594876437452686256689987257070593103236736665428729427619705872943429232655765422570886065530391280346022248754298968644947028776630092034719665288220072614852767523685449271425625621156002440744829779228586371470014104598951740923606264712772871318661087231354572483007088169299732363994105560041691547574286480910859752944790989975568217597020888743178180249780741003");
    private static BigInteger g = new BigInteger("104445508085276708420694807393443640793578177546516669805005719145160372479064536674681191936290563918398797577936907809249382873393657206151352861246279851506526524378413860927310259510101337514871952313993535777967126269258750789757230305379436622100814057070546758651057458598297069278176032072402965400007815966250791473205917272132295447735530216541543440721927013984830419024536298007578517071862458658381327573948854718760491006976584704374430083152247611760538950944873698408704217558452490780375886711834177126381747130667655402093533060075732803277293941738474561046640555259278631432602619129809694677598");

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, ClassNotFoundException, CloneNotSupportedException {
        BigInteger x;
        do {
            x = new BigInteger(2048, new SecureRandom());
        } while (x.compareTo(p.subtract(BigInteger.valueOf(2))) > 0);

        RSA rsa = new RSA();
        rsa.keyGen(2048);
        Socket socket;
        boolean isClient = args.length >= 2;
        if (isClient) {
            //client
            socket = new Socket(args[0], Integer.parseInt(args[1]));

        } else {
            // server
            try (ServerSocket server = new ServerSocket(0)) {
                InetAddress localhost = InetAddress.getLocalHost();
                String localhostAddress = localhost.getHostAddress();
                System.out.println("I'm listening on " + localhostAddress + ":" + server.getLocalPort());
                socket = server.accept();
            }
        }

        try (ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
             ObjectInputStream ois = new ObjectInputStream(socket.getInputStream())) {

            oos.writeObject(rsa.getPk());
            BigInteger gx = g.modPow(x, p);
            oos.writeObject(gx);

            PublicKey pkOther = (PublicKey) ois.readObject();
            BigInteger gxOther = (BigInteger) ois.readObject();

            BigInteger key = gxOther.modPow(x, p);
            PublicKey firstPk, secondPk;
            BigInteger firstGx, secondGx;

            // Make sure we hash in the same order on client and server
            if (isClient) {
                firstPk = rsa.getPk();
                secondPk = pkOther;
                firstGx = gx;
                secondGx = gxOther;

            } else {
                firstPk = pkOther;
                secondPk = rsa.getPk();
                firstGx = gxOther;
                secondGx = gx;
            }

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            // Hash first message client -> server
            sha256.update(firstPk.getE().toByteArray());
            sha256.update(firstPk.getN().toByteArray());
            sha256.update(firstGx.toByteArray());

            // Hash server -> client
            sha256.update(secondPk.getE().toByteArray());
            sha256.update(secondPk.getN().toByteArray());
            sha256.update(secondGx.toByteArray());

            // Save the state for later when we append the
            // finish message
            MessageDigest clonedSha256 = (MessageDigest) sha256.clone();

            byte[] hash = sha256.digest();

            if (isClient) {
                // Client sends its finish message first
                byte[] ourSignature = rsa.sign(hash);
                oos.writeObject(ourSignature);

                // Verify that server sent what we received
                byte[] signature = (byte[]) ois.readObject();
                RSA serverRSA = new RSA(pkOther);
                clonedSha256.update(ourSignature);

                if (!serverRSA.verify(clonedSha256.digest(), signature)) {
                    System.out.println("server couldn't be verified");
                    return;
                }
            } else {
                // Get finish message from client
                byte[] signature = (byte[]) ois.readObject();

                // Verify that client sent what we received
                RSA clientRSA = new RSA(pkOther);
                if (!clientRSA.verify(hash, signature)) {
                    System.out.println("client couldn't be verified");
                    return;
                }

                // Send signature for messages we have received
                clonedSha256.update(signature);
                byte[] weed = clonedSha256.digest();
                oos.writeObject(rsa.sign(weed));
            }

            System.out.println("OK it went without failure - This is the key: " + key);
        }
    }
}
