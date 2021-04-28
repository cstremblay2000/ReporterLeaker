/*
 * @filename ReporterModel.java
 * @author Chris Tremblay (cst1465)
 * @date 4/28/2021, National Superhero Day!
 *
 * Description:
 *  This ReporterModel deals with decrypting the the information sent from
 * the Leaker
 */

import java.math.BigInteger;

/**
 * The ReporterModel takes the BigInteger message and decrypts it using RSA
 * and the decodes it using the OAEP class
 *
 * @author Chris Tremblay (cst1465)
 * @version 4/25/2021
 */
public class ReporterModel implements LeakerListener {

    /** The private exponent */
    private final BigInteger exponent;

    /** The private modulus */
    private final BigInteger modulus;

    /** The OAEP instance */
    private final OAEP oaep;

    /**
     * Create a new ReporterModel
     *
     * @param exponent the private exponent
     * @param modulus the private modulus
     */
    public ReporterModel(BigInteger exponent, BigInteger modulus){
        this.exponent = exponent;
        this.modulus = modulus;
        this.oaep = new OAEP();
    }

    /**
     * Send a message from the Leaker to the Reporter
     *
     * @param bi the encoded, then RSA encrypted BigInteger
     */
    @Override
    public synchronized void report(BigInteger bi) {
        String decrypted = decryptMessage(bi, exponent, modulus, oaep);
        if(decrypted != null)
            System.out.println(decrypted);
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
    private String decryptMessage(BigInteger message, BigInteger exponent,
                                         BigInteger modulus, OAEP oaep){
        // calculate encoded plain text
        BigInteger encoded = message.modPow(exponent, modulus);

        // try decoding plain text
        String plainText = null;
        try{
            plainText = oaep.decode(encoded);
        } catch (Exception e) {
            System.err.println("ERROR");
        }
        return plainText;
    }
}
