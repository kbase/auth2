package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

/* Test creating and getting local and standard users. Does not test any other user manipulations.
 */

public class MongoStorageUserCreateGetTest extends MongoStorageTester {
	
	private static final Instant NOW = Instant.now();
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));

	@Test
	public void createGetLocalUserMinimal() throws Exception {
		final byte[] pwd = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whee".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("local"), new DisplayName("bar"), NOW, pwd, salt)
				.build();
				
		storage.createLocalUser(nlu);
		
		final LocalUser lu = storage.getLocalUser(new UserName("local"));

		assertThat("incorrect password hash",
				new String(lu.getPasswordHash(), StandardCharsets.UTF_8), is("foobarbaz2"));
		assertThat("incorrect password salt",
				new String(lu.getSalt(), StandardCharsets.UTF_8), is("whee"));
		assertThat("incorrect pwd reset", lu.isPwdResetRequired(), is(false));
		assertThat("incorrect reset date", lu.getLastPwdReset(), is(Optional.absent()));
		assertThat("incorrect disable admin", lu.getAdminThatToggledEnabledState(),
				is(Optional.absent()));
		assertThat("incorrect creation", lu.getCreated(), is(NOW));
		assertThat("incorrect custom roles", lu.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", lu.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", lu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", lu.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date",
				lu.getEnableToggleDate(), is(Optional.absent()));
		assertThat("incorrect grantable roles", lu.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", lu.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect policy ids", lu.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", lu.getLastLogin(), is(Optional.absent()));
		assertThat("incorrect disabled reason", lu.getReasonForDisabled(), is(Optional.absent()));
		assertThat("incorrect roles", lu.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", lu.getUserName(), is(new UserName("local")));
		assertThat("incorrect is disabled", lu.isDisabled(), is(false));
		assertThat("incorrect is local", lu.isLocal(), is(true));
		assertThat("incorrect is root", lu.isRoot(), is(false));
	}
	
	@Test
	public void createGetLocalUserMaximal() throws Exception {
		// tests unknown email address
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("baz"), new DisplayName("bang"), Instant.ofEpochMilli(5000),
						pwd, salt)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withRole(Role.ADMIN).withRole(Role.DEV_TOKEN)
				.withCustomRole("foo").withCustomRole("bar")
				.withPolicyID(new PolicyID("pfoo"), Instant.ofEpochMilli(4000))
				.withPolicyID(new PolicyID("pbar"), Instant.ofEpochMilli(6000))
				.withLastLogin(Instant.ofEpochMilli(10000))
				.withUserDisabledState(new UserDisabledState("reason", new UserName("bap"),
						Instant.ofEpochMilli(20000)))
				.withForceReset(true)
				.withLastReset(Instant.ofEpochMilli(30000))
				.build();
		
		storage.setCustomRole(new CustomRole("foo", "baz"));
		storage.setCustomRole(new CustomRole("bar", "baz"));
				
		storage.createLocalUser(nlu);
		
		final LocalUser lu = storage.getLocalUser(new UserName("baz"));
		
		assertThat("incorrect password hash",
				new String(lu.getPasswordHash(), StandardCharsets.UTF_8), is("foobarbaz3"));
		assertThat("incorrect password salt",
				new String(lu.getSalt(), StandardCharsets.UTF_8), is("whoo"));
		assertThat("incorrect pwd reset", lu.isPwdResetRequired(), is(true));
		assertThat("incorrect reset date", lu.getLastPwdReset(),
				is(Optional.of(Instant.ofEpochMilli(30000))));
		assertThat("incorrect disable admin", lu.getAdminThatToggledEnabledState(),
				is(Optional.of(new UserName("bap"))));
		assertThat("incorrect creation", lu.getCreated(), is(Instant.ofEpochMilli(5000)));
		assertThat("incorrect custom roles", lu.getCustomRoles(), is(set("foo", "bar")));
		assertThat("incorrect disabled state", lu.getDisabledState(), is(new UserDisabledState(
				"reason", new UserName("bap"), Instant.ofEpochMilli(20000))));
		assertThat("incorrect display name", lu.getDisplayName(), is(new DisplayName("bang")));
		assertThat("incorrect email", lu.getEmail(), is(new EmailAddress("f@g.com")));
		assertThat("incorrect enable toggle date", lu.getEnableToggleDate(),
				is(Optional.of(Instant.ofEpochMilli(20000))));
		assertThat("incorrect grantable roles", lu.getGrantableRoles(),
				is(set(Role.DEV_TOKEN, Role.SERV_TOKEN)));
		assertThat("incorrect identities", lu.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect policy ids", lu.getPolicyIDs(),
				is(ImmutableMap.of(new PolicyID("pfoo"), Instant.ofEpochMilli(4000),
						new PolicyID("pbar"), Instant.ofEpochMilli(6000))));
		assertThat("incorrect last login", lu.getLastLogin(),
				is(Optional.of(Instant.ofEpochMilli(10000))));
		assertThat("incorrect disabled reason", lu.getReasonForDisabled(),
				is(Optional.of("reason")));
		assertThat("incorrect roles", lu.getRoles(), is(set(Role.ADMIN, Role.DEV_TOKEN)));
		assertThat("incorrect user name", lu.getUserName(), is(new UserName("baz")));
		assertThat("incorrect is disabled", lu.isDisabled(), is(true));
		assertThat("incorrect is local", lu.isLocal(), is(true));
		assertThat("incorrect is root", lu.isRoot(), is(false));
	}
	
	@Test
	public void createNullLocalUser() throws Exception {
		failCreateLocalUser(null, new NullPointerException("local"));
	}
	
	@Test
	public void createLocalUserWithBadCustomRole() throws Exception {
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("baz"), new DisplayName("bang"), NOW, pwd, salt)
				.withCustomRole("Idontexist")
				.build();
				
		failCreateLocalUser(nlu, new NoSuchRoleException("Idontexist"));
	}

	@Test
	public void createExistingLocalUser() throws Exception {
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("baz"), new DisplayName("bang"), NOW, pwd, salt)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withForceReset(true)
				.build();
				
		storage.createLocalUser(nlu);
		
		failCreateLocalUser(nlu, new UserExistsException("baz"));
	}
	
	private void failCreateLocalUser(final LocalUser user, final Exception e)
			throws UserExistsException, AuthStorageException {
		try {
			storage.createLocalUser(user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getNullLocalUser() {
		failGetLocalUser(null, new NullPointerException("userName"));
	}
	
	@Test
	public void getNoSuchLocalUser() throws Exception {
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("baz"), new DisplayName("bang"), NOW, pwd, salt)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withForceReset(true)
				.build();
		
		storage.createLocalUser(nlu);
		failGetLocalUser(new UserName("bar"), new NoSuchUserException("bar"));
	}
	
	@Test
	public void getStdUserAsLocal() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE1).build());
				
		failGetLocalUser(new UserName("foo"), new NoSuchLocalUserException("foo"));
	}
	
	private void failGetLocalUser(final UserName user, final Exception e) {
		try {
			storage.getLocalUser(user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getLocalUserAsStdUser() throws Exception {
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final Instant create = Instant.ofEpochMilli(1000);
		final LocalUser nlu = LocalUser.getBuilder(
				new UserName("baz"), new DisplayName("bang"), create, pwd, salt)
				.withEmailAddress(new EmailAddress("f@g.com"))
				.withPolicyID(new PolicyID("baz"), Instant.ofEpochMilli(5000))
				.withForceReset(true)
				.build();
				
		storage.createLocalUser(nlu);
		
		final AuthUser u = storage.getUser(new UserName("baz"));
		
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.absent()));
		assertThat("incorrect creation", u.getCreated(), is(create));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bang")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.absent()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(ImmutableMap.of(
				new PolicyID("baz"), Instant.ofEpochMilli(5000))));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.absent()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.absent()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("baz")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(true));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	@Test
	public void createGetStdUserMinimal() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user"), new DisplayName("bar"), NOW, REMOTE1)
				.build());

		final AuthUser u = storage.getUser(new UserName("user"));

		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.absent()));
		assertThat("incorrect creation", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.absent()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.absent()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.absent()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("user")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void createGetStdUserMaximal() throws Exception {
		storage.setCustomRole(new CustomRole("crfoo", "baz"));
		storage.setCustomRole(new CustomRole("crbar", "baz"));
		
		// ensure last login is after creation date
		final Instant ll = NOW.plusMillis(10000);
		storage.createUser(NewUser.getBuilder(
				new UserName("user"), new DisplayName("bar"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g.com"))
				.withRole(Role.CREATE_ADMIN)
				.withRole(Role.DEV_TOKEN)
				.withCustomRole("crfoo").withCustomRole("crbar")
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(60000))
				.withPolicyID(new PolicyID("bar"), Instant.ofEpochMilli(70000))
				.withLastLogin(ll)
				.withUserDisabledState(new UserDisabledState(
						"reason", new UserName("baz"), Instant.ofEpochMilli(30000)))
				.build());

		final AuthUser u = storage.getUser(new UserName("user"));

		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.of(new UserName("baz"))));
		assertThat("incorrect creation", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(set("crfoo", "crbar")));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState(
				"reason", new UserName("baz"), Instant.ofEpochMilli(30000))));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(),
				is(Optional.of(Instant.ofEpochMilli(30000))));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(set(Role.ADMIN)));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(ImmutableMap.of(
				new PolicyID("bar"), Instant.ofEpochMilli(70000),
				new PolicyID("foo"), Instant.ofEpochMilli(60000))));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.of(ll)));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(),
				is(Optional.of("reason")));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.CREATE_ADMIN, Role.DEV_TOKEN)));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("user")));
		assertThat("incorrect is disabled", u.isDisabled(), is(true));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void getNullUser() {
		failGetUser(null, new NullPointerException("userName"));
	}
	
	@Test
	public void getNoSuchUser() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.build());

		failGetLocalUser(new UserName("user2"), new NoSuchUserException("user2"));
	}
	
	private void failGetUser(final UserName user, final Exception e) {
		try {
			storage.getUser(user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void createNullUser() throws Exception {
		failCreateUser(null, new NullPointerException("newUser"));
	}
	
	@Test
	public void createUserWithBadCustomRole() throws Exception {
		final NewUser nu = NewUser.getBuilder(
				new UserName("baz"), new DisplayName("bang"), NOW, REMOTE1)
				.withCustomRole("Idontexist")
				.build();
				
		failCreateUser(nu, new NoSuchRoleException("Idontexist"));
	}

	@Test
	public void createExistingUser() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.build());
		
		final RemoteIdentity ri = new RemoteIdentity(
				new RemoteIdentityID("prov2", "bar1"),
				new RemoteIdentityDetails("user1", "full1", "email1"));
		
		final NewUser nu2 = NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, ri)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.build();
		
		failCreateUser(nu2, new UserExistsException("user1"));
	}
	
	@Test
	public void createUserWithExistingRemoteID() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.build());
		
		final RemoteIdentity ri = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar1"),
				new RemoteIdentityDetails("user1", "full1", "email1"));
		
		final NewUser nu2 = NewUser.getBuilder(
				new UserName("user2"), new DisplayName("bar1"), NOW, ri)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.build();
		
		failCreateUser(nu2, new IdentityLinkedException("prov : bar1"));
	}
	
	private void failCreateUser(final NewUser user, final Exception e)
			throws UserExistsException, AuthStorageException {
		try {
			storage.createUser(user);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getUserByRemoteIdMinimal() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.build());
		
		final AuthUser u = storage.getUser(REMOTE1).get();
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.absent()));
		assertThat("incorrect creation", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", u.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is(Optional.absent()));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect policy ids", u.getPolicyIDs(), is(Collections.emptyMap()));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.absent()));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is(Optional.absent()));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("user1")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void getUserByRemoteId2Maximal() throws Exception {
		storage.setCustomRole(new CustomRole("crfoo", "baz"));
		storage.setCustomRole(new CustomRole("crbar", "baz"));
		
		// ensure last login is after creation date
		final Instant ll = NOW.plusMillis(10000);
		storage.createUser(NewUser.getBuilder(
				new UserName("user"), new DisplayName("bar"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g.com"))
				.withRole(Role.CREATE_ADMIN).withRole(Role.DEV_TOKEN)
				.withCustomRole("crfoo").withCustomRole("crbar")
				.withPolicyID(new PolicyID("foo"), Instant.ofEpochMilli(60000))
				.withPolicyID(new PolicyID("bar"), Instant.ofEpochMilli(70000))
				.withLastLogin(ll)
				.withUserDisabledState(new UserDisabledState(
						"reason", new UserName("baz"), Instant.ofEpochMilli(30000)))
				.build());

		storage.link(new UserName("user"), REMOTE2);

		final AuthUser u = storage.getUser(REMOTE2).get();

		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is(Optional.of(new UserName("baz"))));
		assertThat("incorrect creation", u.getCreated(), is(NOW));
		assertThat("incorrect custom roles", u.getCustomRoles(), is(set("crfoo", "crbar")));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState(
				"reason", new UserName("baz"), Instant.ofEpochMilli(30000))));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(),
				is(Optional.of(Instant.ofEpochMilli(30000))));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(set(Role.ADMIN)));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1, REMOTE2)));
		assertThat("incorrect policy ids", u.getPolicyIDs(),is(ImmutableMap.of(
				new PolicyID("bar"), Instant.ofEpochMilli(70000),
				new PolicyID("foo"), Instant.ofEpochMilli(60000))));
		assertThat("incorrect last login", u.getLastLogin(), is(Optional.of(ll)));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(),
				is(Optional.of("reason")));
		assertThat("incorrect roles", u.getRoles(), is(set(Role.CREATE_ADMIN, Role.DEV_TOKEN)));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("user")));
		assertThat("incorrect is disabled", u.isDisabled(), is(true));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void getNonExistentUserByRemoteId() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.build());
		assertThat("incorrect user", storage.getUser(REMOTE2), is(Optional.absent()));
	}
	
	//TODO TEST case where user starts login, stores identity linked to user, id is unlinked, and then completes login. In Authentication tests
	
	@Test
	public void getUserAndUpdateRemoteId() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("user1"), new DisplayName("bar1"), NOW, REMOTE1)
				.withEmailAddress(new EmailAddress("e@g1.com"))
				.build());
		storage.link(new UserName("user1"), REMOTE2);
		
		final RemoteIdentity ri3 = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user3", "full3", "email3"));
		
		final RemoteIdentity expected = new RemoteIdentity(
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user3", "full3", "email3"));
		
		final AuthUser au = storage.getUser(ri3).get();
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect identities", au.getIdentities(), is(set(REMOTE1, expected)));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
		// ok, thats enough
	}
}
