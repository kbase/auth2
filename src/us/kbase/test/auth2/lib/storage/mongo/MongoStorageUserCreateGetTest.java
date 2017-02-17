package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.NewLocalUser;
import us.kbase.auth2.lib.NewRootUser;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.test.auth2.TestCommon;

/* Test creating and getting local and standard users. Does not test any other user manipulations.
 */

public class MongoStorageUserCreateGetTest extends MongoStorageTester {
	
	private static final RemoteIdentityWithLocalID REMOTE1 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentityWithLocalID REMOTE2 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891d56715d8"),
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));

	@Test
	public void createGetLocalUser1() throws Exception {
		final byte[] pwd = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whee".getBytes(StandardCharsets.UTF_8);
		final NewLocalUser nlu = new NewLocalUser(
				new UserName("local"), new EmailAddress("e@g.com"), new DisplayName("bar"),
				pwd, salt, false);
				
		storage.createLocalUser(nlu);
		
		final LocalUser lu = storage.getLocalUser(new UserName("local"));

		assertThat("incorrect password hash",
				new String(lu.getPasswordHash(), StandardCharsets.UTF_8), is("foobarbaz2"));
		assertThat("incorrect password salt",
				new String(lu.getSalt(), StandardCharsets.UTF_8), is("whee"));
		assertThat("incorrect pwd reset", lu.isPwdResetRequired(), is(false));
		assertThat("incorrect reset date", lu.getLastPwdReset(), is((Date) null));
		assertThat("incorrect disable admin", lu.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(lu.getCreated(), 500);
		assertThat("incorrect custom roles", lu.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", lu.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", lu.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", lu.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", lu.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", lu.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", lu.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect last login", lu.getLastLogin(), is((Date) null));
		assertThat("incorrect disabled reason", lu.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", lu.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", lu.getUserName(), is(new UserName("local")));
		assertThat("incorrect is disabled", lu.isDisabled(), is(false));
		assertThat("incorrect is local", lu.isLocal(), is(true));
		assertThat("incorrect is root", lu.isRoot(), is(false));
	}
	
	@Test
	public void createGetLocalUser2() throws Exception {
		// tests unknown email address
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final NewLocalUser nlu = new NewLocalUser(
				new UserName("baz"), EmailAddress.UNKNOWN, new DisplayName("bang"),
				pwd, salt, true);
				
		storage.createLocalUser(nlu);
		
		final LocalUser lu = storage.getLocalUser(new UserName("baz"));
		
		assertThat("incorrect password hash",
				new String(lu.getPasswordHash(), StandardCharsets.UTF_8), is("foobarbaz3"));
		assertThat("incorrect password salt",
				new String(lu.getSalt(), StandardCharsets.UTF_8), is("whoo"));
		assertThat("incorrect pwd reset", lu.isPwdResetRequired(), is(true));
		assertThat("incorrect reset date", lu.getLastPwdReset(), is((Date) null));
		assertThat("incorrect disable admin", lu.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(lu.getCreated(), 500);
		assertThat("incorrect custom roles", lu.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", lu.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", lu.getDisplayName(), is(new DisplayName("bang")));
		assertThat("incorrect email", lu.getEmail(), is(EmailAddress.UNKNOWN));
		assertThat("incorrect enable toggle date", lu.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", lu.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", lu.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect last login", lu.getLastLogin(), is((Date) null));
		assertThat("incorrect disabled reason", lu.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", lu.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", lu.getUserName(), is(new UserName("baz")));
		assertThat("incorrect is disabled", lu.isDisabled(), is(false));
		assertThat("incorrect is local", lu.isLocal(), is(true));
		assertThat("incorrect is root", lu.isRoot(), is(false));
	}
	
	@Test
	public void createGetRootUser() throws Exception {
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final NewRootUser nlu = new NewRootUser(new EmailAddress("f@g.com"),
				new DisplayName("bang"), pwd, salt);
				
		storage.createLocalUser(nlu);
		
		final LocalUser lu = storage.getLocalUser(UserName.ROOT);
		
		assertThat("incorrect password hash",
				new String(lu.getPasswordHash(), StandardCharsets.UTF_8), is("foobarbaz3"));
		assertThat("incorrect password salt",
				new String(lu.getSalt(), StandardCharsets.UTF_8), is("whoo"));
		assertThat("incorrect pwd reset", lu.isPwdResetRequired(), is(false));
		assertThat("incorrect reset date", lu.getLastPwdReset(), is((Date) null));
		assertThat("incorrect disable admin", lu.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(lu.getCreated(), 500);
		assertThat("incorrect custom roles", lu.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", lu.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", lu.getDisplayName(), is(new DisplayName("bang")));
		assertThat("incorrect email", lu.getEmail(), is(new EmailAddress("f@g.com")));
		assertThat("incorrect enable toggle date", lu.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", lu.getGrantableRoles(),
				is(set(Role.CREATE_ADMIN)));
		assertThat("incorrect identities", lu.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect last login", lu.getLastLogin(), is((Date) null));
		assertThat("incorrect disabled reason", lu.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", lu.getRoles(), is(set(Role.ROOT)));
		assertThat("incorrect user name", lu.getUserName(), is(UserName.ROOT));
		assertThat("incorrect is disabled", lu.isDisabled(), is(false));
		assertThat("incorrect is local", lu.isLocal(), is(true));
		assertThat("incorrect is root", lu.isRoot(), is(true));
	}
	
	@Test
	public void createNullLocalUser() throws Exception {
		failCreateLocalUser(null, new NullPointerException("local"));
	}

	@Test
	public void createExistingLocalUser() throws Exception {
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final NewLocalUser nlu = new NewLocalUser(
				new UserName("baz"), new EmailAddress("f@g.com"), new DisplayName("bang"),
				pwd, salt, true);
				
		storage.createLocalUser(nlu);
		
		failCreateLocalUser(nlu, new UserExistsException("baz"));
	}
	
	private void failCreateLocalUser(final NewLocalUser user, final Exception e)
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
		final NewLocalUser nlu = new NewLocalUser(
				new UserName("baz"), new EmailAddress("f@g.com"), new DisplayName("bang"),
				pwd, salt, true);
				
		storage.createLocalUser(nlu);
		failGetLocalUser(new UserName("bar"), new NoSuchUserException("bar"));
	}
	
	@Test
	public void getStdUserAsLocal() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE1, null));
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
		final NewLocalUser nlu = new NewLocalUser(
				new UserName("baz"), new EmailAddress("f@g.com"), new DisplayName("bang"),
				pwd, salt, true);
				
		storage.createLocalUser(nlu);
		
		final AuthUser u = storage.getUser(new UserName("baz"));
		
		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(u.getCreated(), 500);
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bang")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("f@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(Collections.emptySet()));
		assertThat("incorrect last login", u.getLastLogin(), is((Date) null));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("baz")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(true));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void getStdUser() throws Exception {
		// ensure last login is after creation date
		final Date d = new Date(new Date().getTime() + 1000);
		final NewUser nu = new NewUser(new UserName("user"), new EmailAddress("e@g.com"),
				new DisplayName("bar"), REMOTE1, d);
				
		storage.createUser(nu);
		
		final AuthUser u = storage.getUser(new UserName("user"));

		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(u.getCreated(), 1500);
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect last login", u.getLastLogin(), is(d));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("user")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void getStdUserNullLastLogin() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
				
		storage.createUser(nu);
		
		final AuthUser u = storage.getUser(new UserName("user1"));

		assertThat("incorrect disable admin", u.getAdminThatToggledEnabledState(),
				is((UserName) null));
		TestCommon.assertDateNoOlderThan(u.getCreated(), 1500);
		assertThat("incorrect custom roles", u.getCustomRoles(), is(Collections.emptySet()));
		assertThat("incorrect disabled state", u.getDisabledState(), is(new UserDisabledState()));
		assertThat("incorrect display name", u.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", u.getEmail(), is(new EmailAddress("e@g1.com")));
		assertThat("incorrect enable toggle date", u.getEnableToggleDate(), is((Date) null));
		assertThat("incorrect grantable roles", u.getGrantableRoles(),
				is(Collections.emptySet()));
		assertThat("incorrect identities", u.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect last login", u.getLastLogin(), is((Date) null));
		assertThat("incorrect disabled reason", u.getReasonForDisabled(), is((String) null));
		assertThat("incorrect roles", u.getRoles(), is(Collections.emptySet()));
		assertThat("incorrect user name", u.getUserName(), is(new UserName("user1")));
		assertThat("incorrect is disabled", u.isDisabled(), is(false));
		assertThat("incorrect is local", u.isLocal(), is(false));
		assertThat("incorrect is root", u.isRoot(), is(false));
	}
	
	@Test
	public void getNullUser() {
		failGetUser(null, new NullPointerException("userName"));
	}
	
	@Test
	public void getNoSuchUser() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
				
		storage.createUser(nu);
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
		failCreateUser(null, new NullPointerException("user"));
	}

	@Test
	public void createExistingUser() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
				
		storage.createUser(nu);
		
		final RemoteIdentityWithLocalID ri = new RemoteIdentityWithLocalID(
				UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d9"),
				new RemoteIdentityID("prov2", "bar1"),
				new RemoteIdentityDetails("user1", "full1", "email1"));
		
		final NewUser nu2 = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), ri, null);
		
		failCreateUser(nu2, new UserExistsException("user1"));
	}
	
	@Test
	public void createUserWithExistingRemoteID() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
				
		storage.createUser(nu);
		
		final RemoteIdentityWithLocalID ri = new RemoteIdentityWithLocalID(
				UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d9"),
				new RemoteIdentityID("prov", "bar1"),
				new RemoteIdentityDetails("user1", "full1", "email1"));
		
		final NewUser nu2 = new NewUser(new UserName("user2"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), ri, null);
		
		failCreateUser(nu2, new IdentityLinkedException("prov : bar1"));
	}
	
	@Test
	public void createUserWithExistingIdentityLocalID() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
				
		storage.createUser(nu);
		
		final RemoteIdentityWithLocalID ri = new RemoteIdentityWithLocalID(
				UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
				new RemoteIdentityID("prov2", "bar1"),
				new RemoteIdentityDetails("user1", "full1", "email1"));
		
		final NewUser nu2 = new NewUser(new UserName("user2"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), ri, null);
		
		failCreateUser(nu2, new IdentityLinkedException("prov2 : bar1"));
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
	public void getUserByRemoteId() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
		storage.createUser(nu);
		final AuthUser au = storage.getUser(REMOTE1);
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect identities", au.getIdentities(), is(set(REMOTE1)));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
		// ok, thats enough
	}
	
	@Test
	public void getUserByRemoteId2() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
		storage.createUser(nu);
		storage.link(new UserName("user1"), REMOTE2);
		final AuthUser au = storage.getUser(REMOTE2);
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect identities", au.getIdentities(), is(set(REMOTE1, REMOTE2)));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
		// ok, thats enough
	}
	
	@Test
	public void getNonExistentUserByRemoteId() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
		storage.createUser(nu);
		assertThat("incorrect user", storage.getUser(REMOTE2), is((AuthUser) null));
	}
	
	//TODO TEST case where user starts login, stores identity linked to user, id is unlinked, and then completes login. In Authentication tests
	
	@Test
	public void getUserAndUpdateRemoteId() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE1, null);
		storage.createUser(nu);
		storage.link(new UserName("user1"), REMOTE2);
		
		final RemoteIdentityWithLocalID ri3 = new RemoteIdentityWithLocalID(
				UUID.fromString("ec8a91d3-5923-4639-8d12-0891d57715d8"),
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user3", "full3", "email3"));
		
		// note UUID is not updated
		final RemoteIdentityWithLocalID expected = new RemoteIdentityWithLocalID(
				UUID.fromString("ec8a91d3-5923-4639-8d12-0891d56715d8"),
				new RemoteIdentityID("prov", "bar2"),
				new RemoteIdentityDetails("user3", "full3", "email3"));
		
		final AuthUser au = storage.getUser(ri3);
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect identities", au.getIdentities(), is(set(REMOTE1, expected)));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
		// ok, thats enough
	}
}
