package us.kbase.auth2.cryptutils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base32;


/** Generates salts, tokens and temporary passwords randomly using the SHA1PRNG algorithm.
 * @author gaprice@lbl.gov
 *
 */
public class RandomDataGenerator {

	private static final char[] PWD_ALLOWED_CHARS =
			"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789+!@$%&*"
			.toCharArray();
	
	// Inspiration from http://stackoverflow.com/a/41156/643675
	
	// note SecureRandom is thread safe
	private final SecureRandom random;
	
	/** Create a token generator.
	 * @throws NoSuchAlgorithmException if a required algorithm is missing.
	 */
	public RandomDataGenerator() throws NoSuchAlgorithmException {
		// sha1 is ok for generating random bits:
		// http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar1.pdf
		random = SecureRandom.getInstance("SHA1PRNG");
	}
	
	/** Generate a random 160 bit token encoded in Base32.
	 * @return a token.
	 */
	public String getToken() {
		final byte[] b = new byte[20]; //160 bits so 32 b32 chars
		random.nextBytes(b);
		return new Base32().encodeAsString(b);
	}
	
	/** Generate a random password consisting of upper and lower case ascii letters excluding
	 * lower case l and o and uppercase I and O, digits excluding one and zero, and the symbols
	 * +, !, @, $, %, &, and *.
	 * @param length the length of the password to generate, minimum 8.
	 * @return a temporary password.
	 */
	public char[] getTemporaryPassword(final int length) {
		if (length < 8) {
			throw new IllegalArgumentException("length must be > 7");
		}
		final char[] pwd = new char[length];
		for (int i = 0; i < length; i++) {
			final int index = (int) (random.nextDouble() * PWD_ALLOWED_CHARS.length);
			pwd[i] = PWD_ALLOWED_CHARS[index];
		}
		return pwd;
	}
	
	/** Generates a random 64 bit salt.
	 * @return the salt.
	 */
	public byte[] generateSalt() {
		// Generate a 8 byte (64 bit) salt as recommended by RSA PKCS5
		final byte[] salt = new byte[8];
		random.nextBytes(salt);
		return salt;
	}
}
