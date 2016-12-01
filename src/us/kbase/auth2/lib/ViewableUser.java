package us.kbase.auth2.lib;

import java.util.Date;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

/* this is a user profile that the requesting user has permission to view. Fields which the
 * requesting user cannot view will be null.
 * 
 * The user name and display name are never null.
 * 
 * Although ViewableUser and AuthUser do not and should not implement a common Java interface,
 * their interface is identical except that ViewableUser may return null for many fields.
 */

public class ViewableUser {

	//TODO TEST unit test
	//TODO JAVADOC
	
	private final UserName userName;
	private final DisplayName displayName;
	private final boolean local;
	private final AuthUser user;
	
	public ViewableUser(final AuthUser user, boolean fullView) throws AuthStorageException {
		if (user == null) {
			throw new NullPointerException("user");
		}
		this.userName = user.getUserName();
		this.displayName = user.getDisplayName();
		this.local = user.getIdentities().isEmpty();
		if (fullView) {
			this.user = user;
		} else {
			this.user = null;
		}
	}

	public boolean isRoot() {
		return userName.isRoot();
	}
	
	public DisplayName getDisplayName() {
		return displayName;
	}

	public EmailAddress getEmail() {
		return user == null ? null : user.getEmail();
	}

	public UserName getUserName() {
		return userName;
	}

	public boolean isLocal() {
		return local;
	}

	public Set<Role> getRoles() {
		return user == null ? null : user.getRoles();
	}

	public Set<String> getCustomRoles() throws AuthStorageException {
		return user == null ? null : user.getCustomRoles();
	}
	
	public Set<RemoteIdentityWithID> getIdentities() {
		return user == null ? null : user.getIdentities();
	}
	
	public Date getCreated() {
		return user == null ? null : user.getCreated();
	}

	public Date getLastLogin() {
		return user == null ? null : user.getLastLogin();
	}
}
