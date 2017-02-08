package us.kbase.auth2.lib;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

/** A new, non-local user. E.g. the user is associated with at least one 3rd party identity.
 * 
 * Note that since some fields in AuthUser may be lazily fetched from the authentication storage
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
public class NewUser extends AuthUser {
	
	//TODO TESTS
	
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
		super(userName, email, displayName, new HashSet<>(Arrays.asList(remoteIdentity)),
				Collections.emptySet(), new Date(), lastLogin, new UserDisabledState());
		if (remoteIdentity == null) {
			throw new NullPointerException("remoteIdentity");
		}
	}

	@Override
	public Set<String> getCustomRoles() {
		return Collections.emptySet();
	}

}
