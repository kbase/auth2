package us.kbase.test.auth2.ui;

import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.test.auth2.MongoStorageTestManager;

public class UITestUtils {
	
	/** Set up a root account and an admin account and return a token for the admin.
	 * @param manager the mongo test manger containing the mongo storage instance that will be
	 * affected.
	 * @return a new token for an admin called 'admin' with CREATE_ADMIN and ADMIN roles.
	 * @throws Exception if bad things happen.
	 */
	public static IncomingToken getAdminToken(final MongoStorageTestManager manager)
			throws Exception {
		final String rootpwd = "foobarwhoowhee";
		when(manager.mockClock.instant()).thenReturn(Instant.now());
		final Authentication auth = new Authentication(
				manager.storage, set(), AuthExternalConfig.SET_DEFAULT);
		auth.createRoot(new Password(rootpwd.toCharArray()));
		final String roottoken = auth.localLogin(UserName.ROOT,
				new Password(rootpwd.toCharArray()),
				TokenCreationContext.getBuilder().build()).getToken().get().getToken();
		final Password admintemppwd = auth.createLocalUser(
				new IncomingToken(roottoken), new UserName("admin"), new DisplayName("a"),
				new EmailAddress("f@g.com"));
		auth.updateRoles(new IncomingToken(roottoken), new UserName("admin"),
				set(Role.CREATE_ADMIN), set());
		final String adminpwd = "foobarwhoowhee2";
		auth.localPasswordChange(new UserName("admin"), admintemppwd,
				new Password(adminpwd.toCharArray()));
		final String admintoken = auth.localLogin(new UserName("admin"),
				new Password(adminpwd.toCharArray()), TokenCreationContext.getBuilder().build())
				.getToken().get().getToken();
		auth.updateRoles(new IncomingToken(admintoken), new UserName("admin"), set(Role.ADMIN),
				set());
		return new IncomingToken(admintoken);
	}

}
