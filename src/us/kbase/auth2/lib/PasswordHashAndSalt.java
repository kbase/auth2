package us.kbase.auth2.lib;

/** Wrapper around credentials for a user, consisting of a hashed password and a salt used to
 * hash that password.
 * 
 * Note that the password and salt are not copied in the constructor and therefore changes to the
 * input arrays will be reflected in the class. For this reason equals() and hashCode() are not
 * implemented.
 * @author gaprice@lbl.gov
 *
 */
public class PasswordHashAndSalt {
	
	final byte[] passwordHash;
	final byte[] salt;
	
	/** Create user credentials. Note this class can be mutated by manipulating the input arrays.
	 * @param passwordHash the hash of the a user's password.
	 * @param salt the salt used when hashing the password.
	 */
	public PasswordHashAndSalt(byte[] passwordHash, byte[] salt) {
		// what's the right # here? Have to rely on user to some extent
		if (passwordHash == null || passwordHash.length < 10) {
			throw new IllegalArgumentException("passwordHash missing or too small");
		}
		if (salt == null || salt.length < 2) {
			throw new IllegalArgumentException("salt missing or too small");
		}
		this.passwordHash = passwordHash;
		this.salt = salt;
	}

	/** Get the password hash. Note that mutating the returned array will mutate this class.
	 * @return the password hash.
	 */
	public byte[] getPasswordHash() {
		return passwordHash;
	}

	/** Get the salt. Note that mutating the returned array will mutate this class.
	 * @return the salt.
	 */
	public byte[] getSalt() {
		return salt;
	}
	
	/** Zero the contents of the hash and salt arrays. */
	public void clear() {
		Utils.clear(passwordHash);
		Utils.clear(salt);
	}

}
