package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;

public class UserTest {
	
	//TODO NOW authuser, localuser, newlocaluser, newuser, viewableuser

	private class TestAuthUser extends AuthUser {

		public TestAuthUser(
				final UserName userName,
				final EmailAddress email,
				final DisplayName displayName,
				final Set<RemoteIdentityWithLocalID> identities,
				final Set<Role> roles,
				final Date created,
				final Date lastLogin,
				final UserDisabledState disabledState) {
			super(userName, email, displayName, identities, roles, created, lastLogin,
					disabledState);
		}

		@Override
		public Set<String> getCustomRoles() throws AuthStorageException {
			return new HashSet<>(Arrays.asList("foo", "bar"));
		}
	}
	
	@Test
	public void testAuthUserConstruct() {
		//TODO TEST
	}
}
