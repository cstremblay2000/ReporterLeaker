/*
 * @filename ReporterProxy.java
 * @author Chris Tremblay (cst1465)
 * @date 4/28/2021
 *
 * Description:
 *  This hands communication from the Leaker to the Reporter
 */

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

/**
 * The ReporterProxy is what wraps up the BigInteger nicely into a UDP packet
 * and sends it off to the destination
 *
 * @author Chris Tremblay (cst1465)
 * @version 4/28/2021
 */
public class ReporterProxy implements LeakerListener {

    /** The socket to send through */
    private final DatagramSocket socket;

    /** The destination to send to */
    private final InetSocketAddress destination;

    /**
     * Create a new ReporterProxy
     *
     * @param socket the socket to send packet through
     * @param destination where we want to send a packet to
     */
    public ReporterProxy(DatagramSocket socket, InetSocketAddress destination){
        this.socket = socket;
        this.destination = destination;
    }

    /**
     * Send a message from a Leaker to a Reporter
     * @param bi the encoded, then RSA encrypted BigInteger
     */
    @Override
    public void report(BigInteger bi) {
        byte[] buffer = bi.toByteArray();
        try{
            DatagramPacket dp = new DatagramPacket(buffer, 0,
                    buffer.length, destination);
            socket.send(dp);
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
    }
}
