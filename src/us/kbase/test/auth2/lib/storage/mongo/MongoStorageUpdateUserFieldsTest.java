package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageUpdateUserFieldsTest extends MongoStorageTester {

	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void updateNoop() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE, null);
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"), new UserUpdate());
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
	}
	
	@Test
	public void updateDisplay() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE, null);
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"),
				new UserUpdate().withDisplayName(new DisplayName("whee")));
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("whee")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("e@g1.com")));
	}
	
	@Test
	public void updateEmail() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE, null);
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"),
				new UserUpdate().withEmail(new EmailAddress("foobar@baz.com")));
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("bar1")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("foobar@baz.com")));
	}
	
	@Test
	public void updateBoth() throws Exception {
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE, null);
		storage.createUser(nu);
		storage.updateUser(new UserName("user1"),
				new UserUpdate().withEmail(new EmailAddress("foobar@baz.com"))
				.withDisplayName(new DisplayName("herbert")));
		final AuthUser au = storage.getUser(new UserName("user1"));
		assertThat("incorrect username", au.getUserName(), is(new UserName("user1")));
		assertThat("incorrect display name", au.getDisplayName(), is(new DisplayName("herbert")));
		assertThat("incorrect email", au.getEmail(), is(new EmailAddress("foobar@baz.com")));
	}
	
	@Test
	public void updateFailNulls() throws Exception {
		failUpdateUser(null, new UserUpdate().withEmail(new EmailAddress("f@g.com")),
				new NullPointerException("userName"));
		failUpdateUser(new UserName("foo"), null, new NullPointerException("update"));
	}
	
	@Test
	public void updateFailNoSuchUser() throws Exception {
		failUpdateUser(new UserName("foo"), new UserUpdate()
				.withEmail(new EmailAddress("f@g.com")), new NoSuchUserException("foo"));
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
		final NewUser nu = new NewUser(new UserName("user1"), new EmailAddress("e@g1.com"),
				new DisplayName("bar1"), REMOTE, null);
		storage.createUser(nu);
		final Date d = new Date(new Date().getTime() + 1000);
		storage.setLastLogin(new UserName("user1"), d);
		assertThat("incorrect login date", storage.getUser(new UserName("user1")).getLastLogin(),
				is(d));
	}
	
	@Test
	public void lastLoginFailNulls() throws Exception {
		failLastLogin(null, new Date(), new NullPointerException("userName"));
		failLastLogin(new UserName("foo"), null, new NullPointerException("lastLogin"));
	}
	
	@Test
	public void lastLoginFailNoSuchUser() throws Exception {
		failLastLogin(new UserName("foo"), new Date(), new NoSuchUserException("foo"));
	}
	
	private void failLastLogin(final UserName name, final Date d, final Exception e) {
		try {
			storage.setLastLogin(name, d);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
