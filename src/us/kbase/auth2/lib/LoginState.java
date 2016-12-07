package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithID;

public class LoginState {

	//TODO JAVADOC
	//TODO TEST
	
	private final Map<UserName, Set<RemoteIdentityWithID>> userIDs = new HashMap<>();
	private final Map<UserName, AuthUser> users = new HashMap<>();
	private final Set<RemoteIdentityWithID> noUser = new HashSet<>();
	private final String provider;
	private final boolean nonAdminLoginAllowed;

	private LoginState(final String provider, final boolean nonAdminLoginAllowed) {
		this.provider = provider;
		this.nonAdminLoginAllowed = nonAdminLoginAllowed;
	}
	
	public String getProvider() {
		return provider;
	}
	
	public boolean isNonAdminLoginAllowed() {
		return nonAdminLoginAllowed;
	}
	
	public boolean isAdmin(final UserName name) {
		checkUser(name);
		return Role.isAdmin(users.get(name).getRoles());
	}
	
	public Set<RemoteIdentityWithID> getIdentities() {
		return Collections.unmodifiableSet(noUser);
	}
	
	public Set<UserName> getUsers() {
		return Collections.unmodifiableSet(users.keySet());
	}
	
	public AuthUser getUser(final UserName name) {
		checkUser(name);
		return users.get(name);
	}

	private void checkUser(final UserName name) {
		if (!users.containsKey(name)) {
			throw new IllegalArgumentException("No such user: " + name.getName());
		}
	}
	
	public Set<RemoteIdentityWithID> getIdentities(final UserName name) {
		checkUser(name);
		return Collections.unmodifiableSet(userIDs.get(name));
	}
	

	public static class Builder {
		
		private final LoginState ls;

		public Builder(final String provider, final boolean nonAdminLoginAllowed) {
			if (provider == null || provider.trim().isEmpty()) {
				throw new IllegalArgumentException("provider cannot be null or empty");
			}
			ls = new LoginState(provider, nonAdminLoginAllowed);
		}

		public void addIdentity(final RemoteIdentityWithID remoteID) {
			if (remoteID == null) {
				throw new NullPointerException("remoteID");
			}
			checkProvider(remoteID);
			ls.noUser.add(remoteID);
		}

		private void checkProvider(final RemoteIdentityWithID remoteID) {
			if (!ls.provider.equals(remoteID.getRemoteID().getProvider())) {
				throw new IllegalStateException(
						"Cannot have multiple providers in the same login state");
			}
		}

		public void addUser(final AuthUser user, final RemoteIdentityWithID remoteID) {
			if (user == null) {
				throw new NullPointerException("user");
			}
			if (remoteID == null) {
				throw new NullPointerException("remoteID");
			}
			checkProvider(remoteID);
			final UserName name = user.getUserName();
			ls.users.put(name, user);
			if (!ls.userIDs.containsKey(name)) {
				ls.userIDs.put(name, new HashSet<>());
			}
			ls.userIDs.get(name).add(remoteID);
		}

		public LoginState build() {
			return ls;
		}
	}
}
