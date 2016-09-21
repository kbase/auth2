package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import us.kbase.auth2.lib.identity.RemoteIdentityWithID;

public class LinkIdentities {
	
	//TODO TEST
	//TODO JAVADOC
	
	private final AuthUser user;
	private final Set<RemoteIdentityWithID> idents;

	public LinkIdentities(
			final AuthUser user,
			Set<RemoteIdentityWithID> ids) {
		if (user == null) {
			throw new NullPointerException("user");
		}
		if (ids == null) {
			ids = new HashSet<>();
		}
		this.user = user;
		this.idents = Collections.unmodifiableSet(ids);
	}

	public AuthUser getUser() {
		return user;
	}

	public Set<RemoteIdentityWithID> getIdentities() {
		return idents;
	}

}
