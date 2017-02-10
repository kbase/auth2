package us.kbase.test.auth2.lib.storage.mongo;


import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.NewLocalUser;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserDisabledState;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.test.auth2.TestCommon;

/* Test creating and getting local and standard users. Does not test any other user manipulations.
 * Also does not test display name canonicalization.
 * TODO test display name canonicalization.
 */

public class MongoStorageUserCreateGetTest extends MongoStorageTester {
	
	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));

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
		final byte[] pwd = "foobarbaz3".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whoo".getBytes(StandardCharsets.UTF_8);
		final NewLocalUser nlu = new NewLocalUser(
				new UserName("baz"), new EmailAddress("f@g.com"), new DisplayName("bang"),
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
		assertThat("incorrect email", lu.getEmail(), is(new EmailAddress("f@g.com")));
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
				new DisplayName("bar"), REMOTE, null));
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
	
	//TODO NOW TEST add tests for regular users
}
