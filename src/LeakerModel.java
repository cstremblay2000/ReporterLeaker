/*
 * @filename LeakerModel.java
 * @author Chris Tremblay (cst1465)
 * @date 4/28/2021, National Superhero Day!
 *
 * Description:
 *  This is the logic that controls the Leaker. It is in charge of encrypting
 * the message properly
 */

import java.math.BigInteger;
import java.util.Random;

/**
 * The LeakerModel first uses the OAEP to encode the string, then a BigInteger
 * to encrypt the message using RSA
 *
 * @author Chris Tremblay (cst1465)
 * @version 4/28/2021
 */
public class LeakerModel {

    /** The seed size */
    private static final int SEED_SIZE = 32;

    /** The OAEP instance */
    private final OAEP oaep;

    /** The exponent of the reporters public key */
    private final BigInteger exponent;

    /** The modulus of the reporters public key */
    private final BigInteger modulus;

    /** The message the leaker is going to send to the reporter */
    private final String message;

    /** The proxy that is listening to the model */
    private final LeakerListener listener;

    /**
     * Create a new LeakerModel
     *
     * @param exponent the public key exponent
     * @param modulus the public key modulus
     * @param message the message to encrypt
     * @param listener the listened to send the information through
     */
    public LeakerModel(BigInteger exponent, BigInteger modulus, String message,
                       LeakerListener listener){
        this.exponent = exponent;
        this.modulus = modulus;
        this.message = message;
        this.listener = listener;
        this.oaep = new OAEP();
        send();
    }

    /**
     * Send the message. Encrypt it, then pass the BigInt to the proxy
     */
    private void send(){
        BigInteger encrypted = encryptMessage(message);
        listener.report(encrypted);
    }

    /**
     * Encrypt the message
     *
     * @param message The message to encrypt
     * @return the BigInteger that has been encoded and encrypted
     */
    private BigInteger encryptMessage(String message){
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
}
