package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.bson.Document;
import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchLocalUserException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.mongo.Fields;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStoragePasswordTest extends MongoStorageTester {
	
	private static final Instant NOW = Instant.now();

	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void reset() throws Exception {
		final byte[] passwordHash = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW).build(),
				new PasswordHashAndSalt(passwordHash, salt));

		storage.forcePasswordReset(new UserName("foo"));
		
		assertThat("expected forced password reset",
				storage.getLocalUser(new UserName("foo")).isPwdResetRequired(), is(true));
	}
	
	@Test
	public void resetFailNoLocalUser() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
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
		storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW).build(),
				new PasswordHashAndSalt(passwordHash, salt));
		storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foo2"), new DisplayName("bar"), NOW).build(),
				new PasswordHashAndSalt(passwordHash, salt));
		storage.createUser(NewUser.getBuilder(
				new UserName("foo3"), new DisplayName("bar"), NOW, REMOTE).build());
		
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
		storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW).build(),
				new PasswordHashAndSalt(passwordHash, salt));
		final LocalUser user = storage.getLocalUser(new UserName("foo"));
		assertThat("incorrect last reset date", user.getLastPwdReset(), is(Optional.absent()));
		
		final byte[] newPasswordHash = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] newSalt = "wo2".getBytes(StandardCharsets.UTF_8);
		final Instant i = Instant.ofEpochMilli(8000);
		
		when(mockClock.instant()).thenReturn(i);
		
		storage.changePassword(
				new UserName("foo"), new PasswordHashAndSalt(newPasswordHash, newSalt),false);
		final LocalUser updated = storage.getLocalUser(new UserName("foo"));
		final PasswordHashAndSalt creds = storage.getPasswordHashAndSalt(new UserName("foo"));
		assertThat("incorrect pasword",
				new String(creds.getPasswordHash(), StandardCharsets.UTF_8),
				is("foobarbaz2"));
		assertThat("incorrect salt", new String(creds.getSalt(), StandardCharsets.UTF_8),
				is("wo2"));
		assertThat("incorrect force reset", updated.isPwdResetRequired(), is(false));
		assertThat("inccorect reset time", updated.getLastPwdReset(), is(Optional.of(i)));
	}
	
	@Test
	public void changePasswordAndForceReset() throws Exception {
		final byte[] passwordHash = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		storage.createLocalUser(LocalUser.getLocalUserBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW).build(),
				new PasswordHashAndSalt(passwordHash, salt));
		final LocalUser user = storage.getLocalUser(new UserName("foo"));
		assertThat("incorrect last reset date", user.getLastPwdReset(), is(Optional.absent()));
		
		final byte[] newPasswordHash = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] newSalt = "wo2".getBytes(StandardCharsets.UTF_8);
		final Instant i = Instant.ofEpochMilli(8000);
		
		when(mockClock.instant()).thenReturn(i);
		
		storage.changePassword(
				new UserName("foo"), new PasswordHashAndSalt(newPasswordHash, newSalt), true);
		final LocalUser updated = storage.getLocalUser(new UserName("foo"));
		final PasswordHashAndSalt creds = storage.getPasswordHashAndSalt(new UserName("foo"));
		assertThat("incorrect pasword",
				new String(creds.getPasswordHash(), StandardCharsets.UTF_8),
				is("foobarbaz2"));
		assertThat("incorrect salt", new String(creds.getSalt(), StandardCharsets.UTF_8),
				is("wo2"));
		assertThat("incorrect force reset", updated.isPwdResetRequired(), is(true));
		assertThat("inccorect reset time", updated.getLastPwdReset(), is(Optional.of(i)));
	}
	
	@Test
	public void changePasswordFailNulls() throws Exception {
		final byte[] pwd = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(pwd, salt);
		failChangePassword(null, creds, new NullPointerException("userName"));
		failChangePassword(new UserName("bar"), null, new NullPointerException("creds"));
	}
	
	@Test
	public void changePasswordFailNoUser() throws Exception {
		final byte[] pwd = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(pwd, salt);
		failChangePassword(new UserName("foo"), creds, new NoSuchUserException("foo"));
		
	}
	
	@Test
	public void changePasswordFailNoLocalUser() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		final byte[] pwd = "foobarbaz1".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "wo".getBytes(StandardCharsets.UTF_8);
		final PasswordHashAndSalt creds = new PasswordHashAndSalt(pwd, salt);
		failChangePassword(new UserName("foo"), creds, new NoSuchLocalUserException("foo"));
	}
	
	private void failChangePassword(
			final UserName name,
			final PasswordHashAndSalt creds,
			final Exception e) {
		try {
			storage.changePassword(name, creds, false);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	
}
