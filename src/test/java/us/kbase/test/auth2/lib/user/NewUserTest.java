package us.kbase.test.auth2.lib.user;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class NewUserTest {
	
	/* note that this does not replicate the tests from authuser to test the general builder */
	
	private static final UUID UID = UUID.randomUUID();
	
	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("prov42", "bar42"),
			new RemoteIdentityDetails("user42", "full42", "email42"));
	
	@Test
	public void build() throws Exception {
		final Instant now = Instant.now();
		final NewUser u = NewUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("bar"), now, REMOTE)
				.withEmailAddress(new EmailAddress("f@h.com")).build();
		
		// test based on equality vs identity
		assertThat("incorrect anonID", u.getAnonymousID(), is(UUID.fromString(UID.toString())));
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.empty()));
		assertThat("incorrect created", u.getCreated(), is(now));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@h.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.empty()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE)));
		assertThat("incorrect identity", u.getIdentity(), is(REMOTE));
		assertThat("incorrect policy IDs", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.empty()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.empty()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void buildFail() throws Exception {
		failBuild(UserName.ROOT, REMOTE,
				new IllegalArgumentException("Standard users cannot be root"));
		failBuild(new UserName("foo"), null, new NullPointerException("remoteIdentity"));
	}
	
	private void failBuild(
			final UserName userName,
			final RemoteIdentity remoteIdentity,
			final Exception e)
			throws Exception {
		try {
			NewUser.getBuilder(
					userName, UID, new DisplayName("bar"), Instant.now(), remoteIdentity);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
