package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Set;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageUpdateUserFieldsTest extends MongoStorageTester {

	private static final Instant NOW = Instant.now()
			.truncatedTo(ChronoUnit.MILLIS); // mongo truncates
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));
	
	@Test
	public void updateNoop() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"), UserUpdate.getBuilder().build());
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
	}
	
	@Test
	public void updateDisplay() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"),
				UserUpdate.getBuilder().withDisplayName(new DisplayName("whee")).build());
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("whee")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
	}
	
	@Test
	public void updateEmail() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"),
				UserUpdate.getBuilder().withEmail(new EmailAddress("foobar@baz.com")).build());
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("foobar@baz.com")));
	}
	
	@Test
	public void updateBoth() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"),
				UserUpdate.getBuilder().withEmail(new EmailAddress("foobar@baz.com"))
						.withDisplayName(new DisplayName("herbert")).build());
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("herbert")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("foobar@baz.com")));
	}
	
	@Test
	public void updateFailNulls() throws Exception {
		failUpdateUser(null, UserUpdate.getBuilder()
						.withEmail(new EmailAddress("f@g.com")).build(),
				new NullPointerException("userName"));
		failUpdateUser(new UserName("foo"), null, new NullPointerException("update"));
	}
	
	@Test
	public void updateFailNoSuchUser() throws Exception {
		failUpdateUser(new UserName("foo"), UserUpdate.getBuilder()
				.withEmail(new EmailAddress("f@g.com")).build(), new NoSuchUserException("foo"));
	}
	
	private void failUpdateUser(final UserName name, final UserUpdate uu, final Exception e) {
		try {
			storage.updateUser(name, uu);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void lastLogin() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		final Instant d = NOW.plus(Duration.ofHours(2));
		storage.setLastLogin(new UserName("user1"), d);
		assertThat("incorrect login date", storage.getUser(new UserName("user1")).getLastLogin(),
				is(Optional.of(d)));
	}
	
	@Test
	public void lastLoginFailNulls() throws Exception {
		failLastLogin(null, Instant.now(), new NullPointerException("userName"));
		failLastLogin(new UserName("foo"), null, new NullPointerException("lastLogin"));
	}
	
	@Test
	public void lastLoginFailNoSuchUser() throws Exception {
		failLastLogin(new UserName("foo"), Instant.now(), new NoSuchUserException("foo"));
	}
	
	private void failLastLogin(final UserName name, final Instant d, final Exception e) {
		try {
			storage.setLastLogin(name, d);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void addPolicyIDsEmpty() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		storage.addPolicyIDs(new UserName("user1"), Collections.emptySet());
		assertThat("incorrect policyIDs", storage.getUser(new UserName("user1")).getPolicyIDs(),
				is(Collections.emptyMap()));
	}
	
	@Test
	public void addPolicyIDs() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		when(mockClock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		storage.addPolicyIDs(new UserName("user1"), set(new PolicyID("foo"), new PolicyID("bar")));
		assertThat("incorrect policyIDs", storage.getUser(new UserName("user1")).getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("bar"), Instant.ofEpochMilli(10000),
						new PolicyID("foo"), Instant.ofEpochMilli(10000))));
	}
	
	@Test
	public void addPolicyIDsOverwrite() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		when(mockClock.instant()).thenReturn(Instant.ofEpochMilli(10000),
				Instant.ofEpochMilli(10000),
				Instant.ofEpochMilli(20000),
				Instant.ofEpochMilli(20000));
		storage.addPolicyIDs(new UserName("user1"), set(new PolicyID("foo"), new PolicyID("bar")));
		storage.addPolicyIDs(new UserName("user1"), set(new PolicyID("bar"), new PolicyID("baz")));
		assertThat("incorrect policyIDs", storage.getUser(new UserName("user1")).getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("bar"), Instant.ofEpochMilli(10000),
						new PolicyID("foo"), Instant.ofEpochMilli(10000),
						new PolicyID("baz"), Instant.ofEpochMilli(20000))));
	}
	
	@Test
	public void addPolicyIDsOverwriteEmpty() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com")).build();
		storage.createUser(nu);
		when(mockClock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		storage.addPolicyIDs(new UserName("user1"), set(new PolicyID("foo"), new PolicyID("bar")));
		storage.addPolicyIDs(new UserName("user1"), Collections.emptySet());
		assertThat("incorrect policyIDs", storage.getUser(new UserName("user1")).getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("bar"), Instant.ofEpochMilli(10000),
						new PolicyID("foo"), Instant.ofEpochMilli(10000))));
	}
	
	@Test
	public void addPolicyIDsFailNulls() throws Exception {
		failAddPolicyIDs(null, Collections.emptySet(), new NullPointerException("userName"));
		failAddPolicyIDs(new UserName("foo"), null, new NullPointerException("policyIDs"));
		failAddPolicyIDs(new UserName("foo"), set(new PolicyID("foo"), null),
				new NullPointerException("null item in policyIDs"));
	}
	
	@Test
	public void addPolicyIDsFailNoSuchUser() throws Exception {
		when(mockClock.instant()).thenReturn(NOW);
		failAddPolicyIDs(new UserName("foo"), set(new PolicyID("foo")),
				new NoSuchUserException("foo"));
	}
	
	private void failAddPolicyIDs(
			final UserName userName,
			final Set<PolicyID> policyIDs,
			final Exception e) {
		try {
			storage.addPolicyIDs(userName, policyIDs);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void removePolicyID() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.withPolicyID(new PolicyID("foo"), Instant.now())
				.withPolicyID(new PolicyID("bar"), Instant.ofEpochMilli(30000))
				.build();
		storage.createUser(nu);
		final NewUser nu2 = NewUser.getBuilder(
				new UserName("user2"), new DisplayName("bar1"), NOW, REMOTE2)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.withPolicyID(new PolicyID("foo"), Instant.now())
				.withPolicyID(new PolicyID("baz"), Instant.ofEpochMilli(40000))
				.build();
		storage.createUser(nu2);
		
		storage.removePolicyID(new PolicyID("foo"));

		assertThat("incorrect policyIDs", storage.getUser(new UserName("user1")).getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("bar"), Instant.ofEpochMilli(30000))));
		assertThat("incorrect policyIDs", storage.getUser(new UserName("user2")).getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("baz"), Instant.ofEpochMilli(40000))));
	}
	
	@Test
	public void removeUnusedPolicyID() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(20000))
				.withPolicyID(new PolicyID("bar"), Instant.ofEpochMilli(30000))
				.build();
		storage.createUser(nu);
		final NewUser nu2 = NewUser.getBuilder(
				new UserName("user2"), new DisplayName("bar1"), NOW, REMOTE2)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(35000))
				.withPolicyID(new PolicyID("baz"), Instant.ofEpochMilli(40000))
				.build();
		storage.createUser(nu2);
		
		storage.removePolicyID(new PolicyID("bat"));

		assertThat("incorrect policyIDs", storage.getUser(new UserName("user1")).getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("bar"), Instant.ofEpochMilli(30000),
						new PolicyID("foo"), Instant.ofEpochMilli(20000))));
		assertThat("incorrect policyIDs", storage.getUser(new UserName("user2")).getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("baz"), Instant.ofEpochMilli(40000),
						new PolicyID("foo"), Instant.ofEpochMilli(35000))));
	}
	
	@Test
	public void failRemovePolicyID() throws Exception {
		try {
			storage.removePolicyID(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("policyID"));
		}
	}
	
}
