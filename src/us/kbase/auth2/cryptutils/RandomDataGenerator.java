package us.kbase.auth2.cryptutils;

import java.util.UUID;

/** Generates UUIDs, salts, tokens and temporary passwords randomly.
 * @author gaprice@lbl.gov
 *
 */
public interface RandomDataGenerator {

	/** Generate a random 160 bit token encoded in Base32.
	 * @return a token.
	 */
	String getToken();
	
	
	/** Generate a random token encoded in Base32 in multiples of 40 bits / 8 characters.
	 * @param sizeMultiple the size of the token in 40 bit / 8 character increments.
	 * @return a token.
	 */
	String getToken(int sizeMultiple);

	/** Generate a random password consisting of upper and lower case ascii letters excluding
	 * lower case l and o and uppercase I and O, digits excluding one and zero, and the symbols
	 * {@literal +, !, @, $, %, &, and *}.
	 * @param length the length of the password to generate, minimum 8.
	 * @return a temporary password.
	 */
	char[] getTemporaryPassword(int length);

	/** Generates a random 64 bit salt.
	 * @return the salt.
	 */
	byte[] generateSalt();
	
	/** Generates a random UUID.
	 * @return the UUID.
	 */
	UUID randomUUID();

}