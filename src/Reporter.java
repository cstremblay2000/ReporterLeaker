/*
 * @filename Reporter.java
 * @author Chris Tremblay (cst1465)
 * @date 4/13/2021, National Peach Cobbler Day!
 *
 * Description:
 *  The file contains the Reporter class which listens for messages from Leakers
 * on a UDP port. The Reporter decrypts the message and prints it to the console
 */

import java.io.File;
import java.io.FileNotFoundException;
import java.math.BigInteger;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Scanner;

/**
 * The Reporter class reads UDP packets from the socket created from the
 * command line args. The Reporter receives UDP packets and attempts to decrypt
 * them using the RSA algorithm. The UPD payloads are in the form of 256 byte
 * BigInteger. The keys are given from the command line. Once decrypted, the
 * unencrypted BigIntegers are decoded using {@link OAEP} to conver them to a
 * string
 *
 * @author Chris Tremblay (cst1465)
 * @version 4/13/2021
 */
public class Reporter {

    /** The usage message */
    private static final String USAGE = "Usage: java Reporter <rhost> <rport>" +
            " <privatekeyfile>\n";

    /**
     * The driver method
     *
     * @param args the command line args
     */
    public static void main(String[] args) {

        // Get the rhost from command line args
        String rhost = null;
        try {
            rhost = args[0];
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        }

        // Get rport from command line args
        int rport = -1;
        try{
            rport = Integer.parseInt(args[1]);
        } catch( NumberFormatException nfe ) {
            System.err.printf("'%s' not a valid port\n", args[1]);
            System.err.println(USAGE);
            System.exit(1);
        } catch (IndexOutOfBoundsException iob){
            indexOutOfBounds(iob);
        }

        // Try to open the port
        DatagramSocket rsocket = null;
        try {
            rsocket = new DatagramSocket(new InetSocketAddress(rhost,
                    rport));
        } catch (SocketException e) {
            e.printStackTrace(System.err);
            System.err.printf("Could not bind socket to %s:%d\n", rhost, rport);
            System.err.println(USAGE);
            System.exit(1);
        }

        // open private key file
        BigInteger exponent = null;
        BigInteger modulus = null;
        try(
                Scanner s = new Scanner(new File(args[2]))
                ){
            exponent = new BigInteger(s.nextLine());
            modulus = new BigInteger(s.nextLine());
        } catch (FileNotFoundException e) {
            e.printStackTrace(System.err);
            System.err.printf("Could not open file '%s'\n", args[2]);
            System.err.println(USAGE);
            System.exit(1);
        } catch (NumberFormatException nfe){
            nfe.printStackTrace(System.err);
            System.err.println("Invalid private key file");
            System.err.println(USAGE);
            System.exit(1);
        }

        // init model and proxy
        LeakerProxy proxy = new LeakerProxy(rsocket);
        ReporterModel model = new ReporterModel(exponent, modulus);
        proxy.setListener(model);
    }

    /**
     * Decrypts the the message using RSA
     * Once decrypted the value is passed to a decoder function that
     * spits a string representation of the number out
     *
     * @param message the BigInteger ciphertext received
     * @param exponent the exponent for RSA algorithm
     * @param modulus the modulus for the RSA algorithm
     * @param oaep the decoder
     * @return the plaintext
     */
    private static String decryptMessage(BigInteger message,
                                         BigInteger exponent,
                                         BigInteger modulus,
                                         OAEP oaep){
        // calculate encoded plain text
        BigInteger encoded = message.modPow(exponent, modulus);

        // try decoding plain text
        String plainText = null;
        try{
            plainText = oaep.decode(encoded);
        } catch (Exception e) {
            System.out.println("ERROR");
        }
        return plainText;
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
