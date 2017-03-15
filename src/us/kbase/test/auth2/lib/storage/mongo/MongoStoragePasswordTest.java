package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.NewLocalUser;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.mongo.Fields;
import us.kbase.test.auth2.TestCommon;

public class MongoStoragePasswordTest extends MongoStorageTester {
	
	private static final Set<PolicyID> MTPID = Collections.emptySet();
	
	private static final Instant NOW = Instant.now();

	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void reset() throws Exception {
		final byte[] passwordHash = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		storage.createLocalUser(new NewLocalUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), MTPID, NOW, passwordHash, salt, false));
		storage.forcePasswordReset(new UserName("foo"));
		
		assertThat("expected forced password reset",
				storage.getLocalUser(new UserName("foo")).isPwdResetRequired(), is(true));
	}
	
	@Test
	public void resetFailNoLocalUser() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
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
				new DisplayName("bar"), MTPID, NOW, passwordHash, salt, false));
		storage.createLocalUser(new NewLocalUser(new UserName("foo2"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), MTPID, NOW, passwordHash, salt, false));
		storage.createUser(new NewUser(new UserName("foo3"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		
		storage.forcePasswordReset();
		final Document stduser = db.getCollection("users")
				.find(new Document(Fields.USER_NAME, "foo3")).first();
		assertThat("field set on std user", stduser.containsKey(Fields.USER_RESET_PWD), is(false));
		assertThat("expected forced password reset",
				storage.getLocalUser(new UserName("foo")).isPwdResetRequired(), is(true));
		assertThat("expected forced password reset",
				storage.getLocalUser(new UserName("foo2")).isPwdResetRequired(), is(true));
	}
	
	@Test
	public void changePassword() throws Exception {
		final byte[] passwordHash = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		storage.createLocalUser(new NewLocalUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), MTPID, NOW, passwordHash, salt, false));
		final LocalUser user = storage.getLocalUser(new UserName("foo"));
		assertThat("incorrect last reset date", user.getLastPwdReset(), is(Optional.absent()));
		
		final byte[] newPasswordHash = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] newSalt = "wo2".getBytes(StandardCharsets.UTF_8);
		final Instant i = Instant.ofEpochMilli(8000);
		
		when(mockClock.instant()).thenReturn(i);
		
		storage.changePassword(new UserName("foo"), newPasswordHash, newSalt, false);
		final LocalUser updated = storage.getLocalUser(new UserName("foo"));
		assertThat("incorrect pasword", new String(updated.getPasswordHash(), StandardCharsets.UTF_8),
				is("foobarbaz2"));
		assertThat("incorrect salt", new String(updated.getSalt(), StandardCharsets.UTF_8),
				is("wo2"));
		assertThat("incorrect force reset", updated.isPwdResetRequired(), is(false));
		assertThat("inccorect reset time", updated.getLastPwdReset(), is(Optional.of(i)));
	}
	
	@Test
	public void changePasswordAndForceReset() throws Exception {
		final byte[] passwordHash = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		storage.createLocalUser(new NewLocalUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), MTPID, NOW, passwordHash, salt, false));
		final LocalUser user = storage.getLocalUser(new UserName("foo"));
		assertThat("incorrect last reset date", user.getLastPwdReset(), is(Optional.absent()));
		
		final byte[] newPasswordHash = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] newSalt = "wo2".getBytes(StandardCharsets.UTF_8);
		final Instant i = Instant.ofEpochMilli(8000);
		
		when(mockClock.instant()).thenReturn(i);
		
		storage.changePassword(new UserName("foo"), newPasswordHash, newSalt, true);
		final LocalUser updated = storage.getLocalUser(new UserName("foo"));
		assertThat("incorrect pasword", new String(updated.getPasswordHash(), StandardCharsets.UTF_8),
				is("foobarbaz2"));
		assertThat("incorrect salt", new String(updated.getSalt(), StandardCharsets.UTF_8),
				is("wo2"));
		assertThat("incorrect force reset", updated.isPwdResetRequired(), is(true));
		assertThat("inccorect reset time", updated.getLastPwdReset(), is(Optional.of(i)));
	}
	
	@Test
	public void changePasswordFailNulls() throws Exception {
		final byte[] pwd = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		failChangePassword(null, pwd, salt, new NullPointerException("userName"));
		failChangePassword(new UserName("bar"), null, salt,
				new IllegalArgumentException("pwdHash cannot be null or empty"));
		failChangePassword(new UserName("bar"), pwd, null,
				new IllegalArgumentException("salt cannot be null or empty"));
	}
	
	@Test
	public void changePasswordFailEmptyBytes() throws Exception {
		final byte[] pwd = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		failChangePassword(new UserName("bar"), new byte[0], salt,
				new IllegalArgumentException("pwdHash cannot be null or empty"));
		failChangePassword(new UserName("bar"), pwd, new byte[0],
				new IllegalArgumentException("salt cannot be null or empty"));
	}
	
	@Test
	public void changePasswordFailNoUser() throws Exception {
		final byte[] pwd = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		failChangePassword(new UserName("foo"), pwd, salt, new NoSuchUserException("foo"));
		
	}
	
	@Test
	public void changePasswordFailNoLocalUser() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, MTPID, NOW, null));
		final byte[] pwd = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		failChangePassword(new UserName("foo"), pwd, salt, new NoSuchLocalUserException("foo"));
	}
	
	private void failChangePassword(
			final UserName name,
			final byte[] pwd,
			final byte salt[],
			final Exception e) {
		try {
			storage.changePassword(name, pwd, salt, false);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	
}
