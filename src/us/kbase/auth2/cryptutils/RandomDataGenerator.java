package us.kbase.auth2.cryptutils;

/** Generates salts, tokens and temporary passwords randomly.
 * @author gaprice@lbl.gov
 *
 */
public interface RandomDataGenerator {

	/** Generate a random 160 bit token encoded in Base32.
	 * @return a token.
	 */
	String getToken();

	/** Generate a random password consisting of upper and lower case ascii letters excluding
	 * lower case l and o and uppercase I and O, digits excluding one and zero, and the symbols
	 * +, !, @, $, %, &, and *.
	 * @param length the length of the password to generate, minimum 8.
	 * @return a temporary password.
	 */
	char[] getTemporaryPassword(int length);

	/** Generates a random 64 bit salt.
	 * @return the salt.
	 */
	byte[] generateSalt();

}