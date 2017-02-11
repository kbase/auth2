package us.kbase.auth2.lib;

import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

/** A new, non-local user. E.g. the user is associated with at least one 3rd party identity.
 * 
 * @author gaprice@lbl.gov
 *
 */
public class NewUser extends AuthUser {
	
	/** Create a new user.
	 * @param userName the name of the user.
	 * @param email the email address of the user.
	 * @param displayName the display name of the user.
	 * @param remoteIdentity the 3rd party identity associated with this user.
	 * @param lastLogin the date of the user's last login. If this time is before the created
	 * date (e.g. the time this constructor is called) it will be silently modified to match
	 * the creation date.
	 */
	public NewUser(
			final UserName userName,
			final EmailAddress email,
			final DisplayName displayName,
			final RemoteIdentityWithLocalID remoteIdentity,
			final Date lastLogin) {
		super(userName, email, displayName, set(remoteIdentity), null, null,
				new Date(), lastLogin, new UserDisabledState());
	}

	private static Set<RemoteIdentityWithLocalID> set(final RemoteIdentityWithLocalID id) {
		if (id == null) {
			throw new NullPointerException("remoteIdentity");
		}
		return new HashSet<>(Arrays.asList(id));
	}
	
	public RemoteIdentityWithLocalID getIdentity() {
		if (getIdentities().size() != 1) {
			// this is untestable without some nutty reflection stuff, look into it later
			// should never happen since AuthUser is immutable
			throw new IllegalStateException("new user must have exactly one identity");
		}
		return getIdentities().iterator().next();
	}
}
