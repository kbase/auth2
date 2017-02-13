package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;


import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewLocalUser;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.mongo.Fields;
import us.kbase.test.auth2.TestCommon;

public class MongoStoragePasswordTest extends MongoStorageTester {

	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void reset() throws Exception {
		final byte[] passwordHash = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		storage.createLocalUser(new NewLocalUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), passwordHash, salt, false));
		storage.forcePasswordReset(new UserName("foo"));
		
		assertThat("expected forced password reset",
				storage.getLocalUser(new UserName("foo")).isPwdResetRequired(), is(true));
	}
	
	@Test
	public void resetFailNoLocalUser() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, null));
		failReset(new UserName("foo"), new NoSuchLocalUserException("foo"));
	}
	
	@Test
	public void resetFailNoUser() throws Exception {
		failReset(null, new NullPointerException("userName"));
		failReset(new UserName("foo"), new NoSuchUserException("foo"));
	}
	
	private void failReset(final UserName name, final Exception e) {
		try {
			storage.forcePasswordReset(name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void resetAll() throws Exception {
		final byte[] passwordHash = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		storage.createLocalUser(new NewLocalUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), passwordHash, salt, false));
		storage.createLocalUser(new NewLocalUser(new UserName("foo2"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), passwordHash, salt, false));
		storage.createUser(new NewUser(new UserName("foo3"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, null));
		
		storage.forcePasswordReset();
		final Document stduser = db.getCollection("users")
				.find(new Document(Fields.USER_NAME, "foo3")).first();
		assertThat("field set on std user", stduser.containsKey(Fields.USER_RESET_PWD), is(false));
		assertThat("expected forced password reset",
				storage.getLocalUser(new UserName("foo")).isPwdResetRequired(), is(true));
		assertThat("expected forced password reset",
				storage.getLocalUser(new UserName("foo2")).isPwdResetRequired(), is(true));
	}
	
}
