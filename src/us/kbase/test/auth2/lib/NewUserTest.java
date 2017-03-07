package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;

public class NewUserTest {
	
	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4638-8d12-0891c56715d8"),
			new RemoteIdentityID("prov42", "bar42"),
			new RemoteIdentityDetails("user42", "full42", "email42"));
	
	@Test
	public void constructorNoLastLogin() throws Exception {
		final Instant now = Instant.now();
		final NewUser u = new NewUser(new UserName("foo"), new EmailAddress("e@g.com"),
				new DisplayName("bar"), REMOTE, now, null);
		
		//check that super() is called correctly
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.absent()));
		assertThat("incorrect created", u.getCreated(), is(now));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.absent()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE)));
		assertThat("incorrect identity", u.getIdentity(), is(REMOTE));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.absent()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.absent()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void constructorWithLastLogin() throws Exception {
		final Instant create = Instant.ofEpochMilli(4000);
		final Optional<Instant> ll = Optional.of(Instant.ofEpochMilli(6000));
		final NewUser u = new NewUser(new UserName("foo"), new EmailAddress("e@g.com"),
				new DisplayName("bar"), REMOTE, create, ll);
		
		//check that super() is called correctly
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.absent()));
		assertThat("incorrect created", u.getCreated(), is(create));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.absent()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE)));
		assertThat("incorrect identity", u.getIdentity(), is(REMOTE));
		assertThat("incorrect last login", u.getLastLogin(), is(ll));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.absent()));
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
					new DisplayName("bar"), null, Instant.now(), null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("remoteIdentity"));
		}
	}
	
}
