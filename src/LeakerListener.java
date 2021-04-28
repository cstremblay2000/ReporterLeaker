/*
 * @filename LeakerListener.java
 * @author Chris Tremblay (cst1465)
 * @date 4/28/2021, National Superhero Day!
 *
 * Description:
 *  This class is a functional interface that describes what a leaker can do
 * to a reporter
 */

import java.math.BigInteger;

/**
 * A Leaker can report something to a Reporter using BigInteger as the
 * encrypted message
 *
 * @author Chris Tremblay (cst1465)
 * @version 4/218/2021
 */
public interface LeakerListener {

    void report(BigInteger bi);

}
