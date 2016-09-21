package us.kbase.auth2.cryptutils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base32;


public class TokenGenerator {

	private static final char[] PWD_ALLOWED_LETTERS =
			"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789+!@$%&*"
			.toCharArray();
	
	//TODO TEST unit tests
	//TODO JAVADOC
	
	// Inspiration from http://stackoverflow.com/a/41156/643675
	
	// note SecureRandom is thread safe
	private final SecureRandom random;
	
	public TokenGenerator() throws NoSuchAlgorithmException {
		random = SecureRandom.getInstance("SHA1PRNG");
	}
	
	public String getToken() {
		final byte[] b = new byte[20]; //160 bits so 32 b32 chars
		random.nextBytes(b);
		return new Base32().encodeAsString(b);
	}
	
	public char[] getTemporaryPassword(final int length) {
		if (length < 8) {
			throw new IllegalArgumentException("length must be > 7");
		}
		final char[] pwd = new char[length];
		for (int i = 0; i < length; i++) {
			final int index = (int) (random.nextDouble() *
					PWD_ALLOWED_LETTERS.length);
			pwd[i] = PWD_ALLOWED_LETTERS[index];
		}
		return pwd;
	}
}
