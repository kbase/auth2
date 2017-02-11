package us.kbase.auth2.lib;

import java.util.Date;
import java.util.Set;

/** A local user.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class LocalUser extends AuthUser {
	
	private final byte[] passwordHash;
	private final byte[] salt;
	private final boolean forceReset;
	private final Long lastReset;
	
	/** Create a new local user.
	 * @param userName the name of the user.
	 * @param email the email address of the user.
	 * @param displayName the display name of the user.
	 * @param roles any roles the user possesses.
	 * @param customRoles any custom roles the user possesses.
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
			final Set<String> customRoles,
			final Date created,
			final Date lastLogin,
			final UserDisabledState disabledState,
			final byte[] passwordHash,
			final byte[] salt,
			final boolean forceReset,
			final Date lastReset) {
		super(userName, email, displayName, null, roles, customRoles, created, lastLogin,
				disabledState);
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
	
	//TODO EQUALS
}
