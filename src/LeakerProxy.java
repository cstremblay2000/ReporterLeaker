/*
 * @filename LeakerProxy.java
 * @author Chris Tremblay (cst1465)
 * @date 4/28/2021, National Superhero Day
 *
 * Description:
 *  The LeakerProxy takes care of all communications that the Reporter receives
 * from the Leaker
 */

import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.Arrays;

/**
 * The LeakerProxy has an encapsulated DatagramSocket that listens for packets
 * sent to the Reporter then extracts the information and gives it to the
 * listener
 *
 * @author Chris Tremblay (cst1465)
 * @version 4/28/2021
 */
public class LeakerProxy {

    /** The buffer size */
    private static final int BUFFER_SIZE = 260;

    /** The socket to send through */
    private final DatagramSocket socket;

    /** The listener */
    private LeakerListener listener;

    /**
     * Create a new LeakerProxy
     *
     * @param socket the socket
     */
    public LeakerProxy(DatagramSocket socket){
        this.socket = socket;
    }

    /**
     * Set the listener, and once the listener is known then spin up a thread
     * that listens for UDP packets
     *
     * @param listener the listner that will take the info from the packet
     */
    public void setListener(LeakerListener listener){
        this.listener = listener;
        new ReaderThread().start();
    }

    /**
     * This class is a thread that listens for a UDP packet on the given
     * socket
     *
     * @author Chris Tremblay
     * @version 4/28/2021
     */
    private class ReaderThread extends Thread{
        public void run(){
            byte[] buffer = new byte[BUFFER_SIZE];
            BigInteger lMessage;
            while(true) {
                try {
                    // get the datagram packet with the encrypted message
                    DatagramPacket dp = new DatagramPacket(buffer, 0, buffer.length);
                    socket.receive(dp);

                    // get payload
                    byte[] payload = Arrays.copyOf(buffer, dp.getLength());
                    lMessage = new BigInteger(payload);
                    listener.report(lMessage);
                } catch (IOException ignored) {
                    // ignore an error receiving packet
                } catch (NumberFormatException nfe){
                    System.err.println("ERROR");
                }
            }
        }
    }
}
