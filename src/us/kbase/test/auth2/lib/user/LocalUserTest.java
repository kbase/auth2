package us.kbase.test.auth2.lib.user;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.Optional;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.test.auth2.TestCommon;

public class LocalUserTest {
	
	/* note that this does not replicate the tests from authuser to test the general builder */
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(LocalUser.class).usingGetClass()
				.withIgnoredFields("canGrantRoles").verify();
	}
	
	@Test
	public void constructMinimal() throws Exception {
		final LocalUser lu = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.ofEpochMilli(5))
				.build();
		
		assertThat("incorrect pwd reset", lu.isPwdResetRequired(), is(false));
		assertThat("incorrect reset date", lu.getLastPwdReset(), is(Optional.empty()));
		
		assertThat("incorrect disable admin", lu.getAdminThatToggledEnabledState(),
				is(Optional.empty()));
		assertThat("incorrect created date", lu.getCreated(), is(Instant.ofEpochMilli(5)));
		assertThat("incorrect custom roles", lu.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", lu.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", lu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", lu.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date", lu.getEnableToggleDate(),
				is(Optional.empty()));
		assertThat("incorrect grantable roles", lu.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", lu.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect policy IDs", lu.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", lu.getLastLogin(), is(Optional.empty()));
		assertThat("incorrect disabled reason", lu.getReasonForDisabled(), is(Optional.empty()));
		assertThat("incorrect roles", lu.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", lu.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", lu.isDisabled(), is(false));
		assertThat("incorrect is local", lu.isLocal(), is(true));
		assertThat("incorrect is root", lu.isRoot(), is(false));
	}
	
	@Test
	public void constructMaximal() throws Exception {
		final LocalUser lu = LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), Instant.ofEpochMilli(5))
				.withEmailAddress(new EmailAddress("f@h.com"))
				.withRole(Role.CREATE_ADMIN)
				.withCustomRole("foobar")
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(70000))
				.withLastLogin(Instant.ofEpochMilli(6000))
				.withUserDisabledState(new UserDisabledState(new UserName("who"),
						Instant.ofEpochMilli(10000)))
				.withForceReset(true)
				.withLastReset(Instant.ofEpochMilli(40000))
				.build();
		
		assertThat("incorrect pwd reset", lu.isPwdResetRequired(), is(true));
		assertThat("incorrect reset date", lu.getLastPwdReset(),
				is(Optional.of(Instant.ofEpochMilli(40000))));
		
		assertThat("incorrect disable admin", lu.getAdminThatToggledEnabledState(),
				is(Optional.of(new UserName("who"))));
		assertThat("incorrect created date", lu.getCreated(), is(Instant.ofEpochMilli(5)));
		assertThat("incorrect custom roles", lu.getCustomRoles(), is(set("foobar")));
		assertThat("incorrect disabled state", lu.getDisabledState(), is(new UserDisabledState(
				new UserName("who"), Instant.ofEpochMilli(10000))));
		assertThat("incorrect display name", lu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", lu.getEmail(), is(new EmailAddress("f@h.com")));
		assertThat("incorrect enable toggle date", lu.getEnableToggleDate(),
				is(Optional.of(Instant.ofEpochMilli(10000))));
		assertThat("incorrect grantable roles", lu.getGrantableRoles(), is(set(Role.ADMIN)));
		assertThat("incorrect identities", lu.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect policy IDs", lu.getPolicyIDs(), is(ImmutableMap.of(
				new PolicyID("foo"), Instant.ofEpochMilli(70000))));
		assertThat("incorrect last login", lu.getLastLogin(),
				is(Optional.of(Instant.ofEpochMilli(6000))));
		assertThat("incorrect disabled reason", lu.getReasonForDisabled(), is(Optional.empty()));
		assertThat("incorrect roles", lu.getRoles(), is(set(Role.CREATE_ADMIN)));
		assertThat("incorrect user name", lu.getUserName(), is(new UserName("foo")));
		assertThat("incorrect is disabled", lu.isDisabled(), is(false));
		assertThat("incorrect is local", lu.isLocal(), is(true));
		assertThat("incorrect is root", lu.isRoot(), is(false));
	}
	
	@Test
	public void buildFail() throws Exception {
		try {
			LocalUser.getLocalUserBuilder(
					new UserName("foo"), new DisplayName("bar"), Instant.ofEpochMilli(5))
					.withLastReset(null)
					.build();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("lastReset"));
		}
	}
}
