package us.kbase.auth2.cryptutils;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Generates and checks salted passwords.
 * 
 * PBKDF2WithHmacSHA256 with 20000 iterations is used for encrypting passwords.
 * SHA1PRNG is used with the SecureRandom class for generating salts.
 * 
 * The code is slightly modified from
 * https://www.javacodegeeks.com/2012/05/secure-password-storage-donts-dos-and.html
 * 
 * @author gaprice@lbl.gov
 *
 */
public class PasswordCrypt {
	
	// PBKDF2 with SHA-256 as the hashing algorithm.
	private static final String CRYPTALG = "PBKDF2WithHmacSHA256";
	// sha256 will make 256 byte keys, surprisingly
	private static final int DERIVED_KEY_LENGTH = 256;
	/* The NIST recommends at least 1,000 iterations:
	 * http://csrc.nist.gov/publications/nistpubs/800-132/nist-sp800-132.pdf
	 * iOS 4.x reportedly uses 10,000:
	 * http://blog.crackpassword.com/2010/09/smartphone-forensics-cracking-blackberry-backup-passwords/
	 */
	private static final int ITERATIONS = 20000;
	
	// VERY important to use SecureRandom instead of just Random
	// note SecureRandom is thread safe
	private final SecureRandom random;

	/** Create a new password crypt instance.
	 * @throws NoSuchAlgorithmException if one of the required cryptography algorithms is not
	 * available.
	 */
	public PasswordCrypt() throws NoSuchAlgorithmException {
		random = SecureRandom.getInstance("SHA1PRNG");
		// not clear if this is thread safe. Doesn't explicitly say so.
		SecretKeyFactory.getInstance(CRYPTALG); // fail early
	}
	
	/** Checks a password matches an encrypted password.
	 * @param attemptedPassword the password.
	 * @param encryptedPassword the password encrypted by this module.
	 * @param salt the salt used to encrypt the password.
	 * @return true if the password matches the encrypted password, false otherwise.
	 */
	public boolean authenticate(
			final char[] attemptedPassword,
			final byte[] encryptedPassword,
			final byte[] salt) {
		// Encrypt the clear-text password using the same salt that was used to
		// encrypt the original password
		byte[] encryptedAttemptedPassword = getEncryptedPassword(attemptedPassword, salt);

		// Authentication succeeds if encrypted password that the user entered
		// is equal to the stored hash
		return equals(encryptedPassword, encryptedAttemptedPassword);
	}

	/* pass all the way through the array rather than stopping at the first
	 * error as this allows for a timing attack
	 * https://crackstation.net/hashing-security.htm
	 */
	private boolean equals(
			final byte[] encryptedPassword,
			final byte[] encryptedAttemptedPassword) {
		// encryptedAttemptedPassword cannot be null at this point, only called from authenticate()
		if (encryptedPassword == null) {
			throw new NullPointerException("Passwords cannot be null");
		}
		final int len = encryptedAttemptedPassword.length > encryptedPassword.length ?
				encryptedAttemptedPassword.length : encryptedPassword.length;
		boolean eq = true;
		for (int i = 0; i < len; i++)
			if (i >= encryptedPassword.length || i >= encryptedAttemptedPassword.length) {
				eq = false;
			} else if (encryptedAttemptedPassword[i] != encryptedPassword[i]) {
				eq = false;
			}
		return eq;
	}

	/** Encrypt a password.
	 * @param password the password to encrypt.
	 * @param salt the salt with which to encrypt the password.
	 * @return the encrypted password.
	 */
	public byte[] getEncryptedPassword(char[] password, byte[] salt) {
		if (password == null || salt == null) {
			throw new NullPointerException("password and salt cannot be null");
		}
		if (password.length < 1) {
			throw new IllegalArgumentException("password must be at least 1 character");
		}
		if (salt.length < 1) {
			throw new IllegalArgumentException("salt must be at least 1 byte");
		}
		final KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, DERIVED_KEY_LENGTH);
		try {
			return SecretKeyFactory.getInstance(CRYPTALG).generateSecret(spec).getEncoded();
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException("This should never happen", e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(
					"checked alg existed at startup, now it doesn't. That's annoying", e);
		}
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
