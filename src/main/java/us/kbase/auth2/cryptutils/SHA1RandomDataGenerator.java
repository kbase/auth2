package us.kbase.auth2.cryptutils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;

import org.apache.commons.codec.binary.Base32;


/** Generates salts, tokens and temporary passwords randomly using the SHA1PRNG algorithm, and
 * UUIDs with the UUID.randomUUID() method.
 * @author gaprice@lbl.gov
 *
 */
public class SHA1RandomDataGenerator implements RandomDataGenerator {

	private static final char[] PWD_ALLOWED_CHARS =
			"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789+!@$%&*"
			.toCharArray();
	
	// Inspiration from http://stackoverflow.com/a/41156/643675
	
	// note SecureRandom is thread safe
	private final SecureRandom random;
	
	/** Create a random data generator.
	 * @throws NoSuchAlgorithmException if a required algorithm is missing.
	 */
	public SHA1RandomDataGenerator() throws NoSuchAlgorithmException {
		// sha1 is ok for generating random bits:
		// http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-131Ar1.pdf
		random = SecureRandom.getInstance("SHA1PRNG");
	}
	
	@Override
	public String getToken() {
		return getToken(4); //160 bits so 32 b32 chars
	}
	
	@Override
	public String getToken(final int sizeMultiple) {
		if (sizeMultiple < 1) {
			throw new IllegalArgumentException("sizeMultiple must be > 0");
		}
		final byte[] b = new byte[sizeMultiple * 5]; // 40 bits / 8 b32 chars per sizeMultiple
		random.nextBytes(b);
		return new Base32().encodeAsString(b);
	}
	
	@Override
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
	
	@Override
	public byte[] generateSalt() {
		// Generate a 8 byte (64 bit) salt as recommended by RSA PKCS5
		final byte[] salt = new byte[8];
		random.nextBytes(salt);
		return salt;
	}
	
	@Override
	public UUID randomUUID() {
		return UUID.randomUUID();
	}
}
