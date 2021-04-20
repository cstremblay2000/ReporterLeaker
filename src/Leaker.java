/*
 * @filename Leaker.java
 * @author Chris Tremblay (cst1465)
 * @date 4/13/2021, National Peach Cobbler Day!
 *
 * Description:
 *  The Leaker sends encrypted UDP messages to a Reporter
 */

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Random;
import java.util.Scanner;

/**
 * The Leaker class send a UDP packet to a Reporter. The string is read from
 * the command line and then encoded using the {@link OAEP} class to transform
 * it into a BigInteger. Once converted to a BigInteger, the RSA algorithm
 * is applied to it using the keys read from the command line args. Once
 * encrypted it is packed up nicely into a UDP packet and sent to the reporter
 *
 * @author Chris Tremblay (cst1465)
 * @version 4/13/2021
 */
public class Leaker {

    /** The usage message */
    private static final String USAGE = "Usage: java Leaker <rhost> <rport> " +
            "<lhost> <lport> <publickeyfile> <message>\n";

    /** The seed size */
    private static final int SEED_SIZE = 32;

    /**
     * The driver function
     *
     * @param args the command line args
     */
    public static void main(String[] args) {

        // Get rhost
        String rhost = null;
        try{
            rhost = args[0];
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        }

        // Get rport
        int rport = 0;
        try{
            rport = parseInt(args[1]);
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        }

        // get lhost
        String lhost = null;
        try{
            lhost = args[2];
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        }

        // get lport
        int lport = 0;
        try {
            lport = parseInt(args[3]);
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        }

        // make lsocket
        DatagramSocket lsocket = makeSocket(lhost, lport);

        // Try to read private key file
        BigInteger exponent = null;
        BigInteger modulus = null;
        try(
                Scanner s = new Scanner(new File(args[4]))
                ){
            exponent = new BigInteger(s.nextLine());
            modulus = new BigInteger(s.nextLine());
        } catch (FileNotFoundException e) {
            e.printStackTrace(System.err);
            System.err.printf("Could not open file '%s'\n", args[4]);
            System.err.println(USAGE);
            System.exit(1);
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        } catch (NumberFormatException nfe) {
            nfe.printStackTrace(System.err);
            System.err.printf("file '%s' has invalid keys\n", args[4]);
            System.err.println(USAGE);
            System.exit(1);
        }

        // the message
        if(args.length > 6){
            System.err.println("Please wrap message in quotes");
            System.err.println(USAGE);
            System.exit(1);
        }

        String message = null;
        try{
            message = args[5];
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        }

        // Encrypt the message
        BigInteger encryptedMessage = encryptMessage(message, exponent, modulus);

        // Create datagram
        byte[] buffer = encryptedMessage.toByteArray();
        try{
            DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length,
                    new InetSocketAddress(rhost, rport));
            lsocket.send(dp);
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }

    /**
     * Encrypt the message
     *
     * @param message The message to encrypt
     * @param exponent the Reporters public key exponent
     * @param modulus the Reporters public key modulus
     * @return the BigInteger that has been encoded and encrypted
     */
    private static BigInteger encryptMessage(String message,
                                             BigInteger exponent,
                                             BigInteger modulus){
        // initialize encoder
        OAEP oaep = new OAEP();

        // Create random seed
        Random random = new Random();
        byte[] seed = new byte[SEED_SIZE];
        for(int i = 0; i < seed.length; i++)
            seed[i] = (byte)random.nextInt();

        // BigInteger encodedMessage = oaep
        BigInteger encoded = oaep.encode(message, seed);

        // encrypt message and return
        return encoded.modPow(exponent, modulus);
    }

    /**
     * Made this to de-clutter the main method, just parse int function
     *
     * @param str the string to try to parse into an int
     * @return the integer (hopefully)
     */
    private static int parseInt(String str){
        try{
            return Integer.parseInt(str);
        } catch (NumberFormatException nfe ){
            nfe.printStackTrace(System.err);
            System.err.printf("'%s' not a valid port\n", str);
            System.err.println(USAGE);
            System.exit(1);
        }
        return -1;
    }

    /**
     * De-clutter the main method by using this function
     *
     * @param host the host to bind to
     * @param port the port on the host to bind to
     * @return the DatagramSocket to that host and port (hopefully)
     */
    private static DatagramSocket makeSocket(String host, int port){
        try{
            return new DatagramSocket(new InetSocketAddress(host, port));
        } catch (SocketException e) {
            e.printStackTrace();
            System.err.printf("Could not bind to %s:%d\n", host, port);
            System.err.println(USAGE);
            System.exit(1);
        }
        return null;
    }

    /**
     * Reports an index out of bounds exception
     *
     * @param iob the exception
     */
    private static void indexOutOfBounds(IndexOutOfBoundsException iob){
        iob.printStackTrace(System.err);
        System.err.println("Missing arguments");
        System.err.println(USAGE);
        System.exit(1);
    }
}
