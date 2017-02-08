package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.test.auth2.TestCommon;

public class NewUserTest {
	
	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4638-8d12-0891c56715d8"),
			new RemoteIdentityID("prov42", "bar42"),
			new RemoteIdentityDetails("user42", "full42", "email42"));
	
	@Test
	public void constructorNoLastLogin() throws Exception {
		final NewUser u = new NewUser(new UserName("foo"), new EmailAddress("e@g.com"),
				new DisplayName("bar"), REMOTE, null);
		
		//check that super() is called correctly
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(u.getCreated(), 500);
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState().getByAdmin(),
				is((UserName) null));
		assertThat("incorrect disabled state", u.getDisabledState().getDisabledReason(),
				is((String) null));
		assertThat("incorrect disabled state", u.getDisabledState().getTime(), is((Date) null));
		assertThat("incorrect disabled state", u.getDisabledState().isDisabled(), is(false));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE)));
		assertThat("incorrect last login", u.getLastLogin(), is((Date) null));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void constructorWithLastLogin() throws Exception {
		final Date ll = new Date(new Date().getTime() + 2000);
		final NewUser u = new NewUser(new UserName("foo"), new EmailAddress("e@g.com"),
				new DisplayName("bar"), REMOTE, ll);
		
		//check that super() is called correctly
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(u.getCreated(), 500);
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState().getByAdmin(),
				is((UserName) null));
		assertThat("incorrect disabled state", u.getDisabledState().getDisabledReason(),
				is((String) null));
		assertThat("incorrect disabled state", u.getDisabledState().getTime(), is((Date) null));
		assertThat("incorrect disabled state", u.getDisabledState().isDisabled(), is(false));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE)));
		assertThat("incorrect last login", u.getLastLogin(), is(ll));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void constructorFail() throws Exception {
		try {
			new NewUser(new UserName("foo"), new EmailAddress("e@g.com"),
					new DisplayName("bar"), null, null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("remoteIdentity"));
		}
	}


}
