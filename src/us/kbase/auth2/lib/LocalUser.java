package us.kbase.auth2.lib;

import java.util.Date;
import java.util.Set;

/** A local user.
 * 
 * Note that since some fields in LocalUser may be lazily fetched from the authentication storage
 * system, equals() and hashcode() are not implemented, as they would require database access when
 * often the fields are not actually necessary for the operation in process.
 * 
 * Usernames are expected to be unique, so testing for equality via comparison of the username is
 * a reasonable substitute, although care must be taken to never initialize a user with an
 * incorrect username.
 * 
 * @author gaprice@lbl.gov
 *
 */
public abstract class LocalUser extends AuthUser {
	
	private final byte[] passwordHash;
	private final byte[] salt;
	private final boolean forceReset;
	private final Long lastReset;
	
	/** Create a new local user.
	 * @param userName the name of the user.
	 * @param email the email address of the user.
	 * @param displayName the display name of the user.
	 * @param roles any roles the user possesses.
	 * @param created the date the user account was created.
	 * @param lastLogin the date of the user's last login.
	 * @param disabledState whether the user account is disabled.
	 * @param passwordHash a salted, hashed password for the user.
	 * @param salt the salt for the hashed password. 
	 * @param forceReset whether the user is required to reset their password on the next login.
	 * @param lastReset the date of the last password reset.
	 */
	public LocalUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final Set<Role> roles,
			final Date created,
			final Date lastLogin,
			final UserDisabledState disabledState,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset,
			final Date lastReset) {
		super(userName, email, displayName, null, roles, created, lastLogin, disabledState);
		// what's the right # here? Have to rely on user to some extent
		if (passwordHash == null || passwordHash.length < 10) {
			throw new IllegalArgumentException("passwordHash missing or too small");
		}
		if (salt == null || salt.length < 2) {
			throw new IllegalArgumentException("salt missing or too small");
		}
		this.passwordHash = passwordHash;
		this.salt = salt;
		this.forceReset = forceReset;
		this.lastReset = lastReset == null ? null : lastReset.getTime();
	}

	/** Get the salted hash of the user's password.
	 * @return the password.
	 */
	public byte[] getPasswordHash() {
		return passwordHash;
	}

	/** Get the salt for the user's password.
	 * @return the password's salt.
	 */
	public byte[] getSalt() {
		return salt;
	}

	/** Check if a password reset is required on next login.
	 * @return true if a reset is required, or false otherwise.
	 */
	public boolean isPwdResetRequired() {
		return forceReset;
	}
	
	/** The date of the last password reset.
	 * @return the last password reset date or null if the password has never been reset.
	 */
	public Date getLastPwdReset() {
		return lastReset == null ? null : new Date(lastReset);
	}
}
