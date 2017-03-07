package us.kbase.test.auth2.lib.storage.mongo;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.test.auth2.TestCommon;

/* Tests the case where somehow invalid data gets into the DB and a container class throws an
 * error on instantiation. This should never happen under normal circumstances, and if it does it
 * means there's a pretty severe bug somewhere in the system.
 * 
 * Note that there are many ways (too many to reasonably test) that the methods that produce
 * these errors can be called. Here we test with the getUser().
 */
public class MongoStorageInvalidDBDataTest extends MongoStorageTester {
	
	private static final Instant NOW = Instant.now();

	private static final RemoteIdentityWithLocalID REMOTE = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void missingUserName() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("user", null)));
		
		failGetUser(REMOTE, new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: user name"));
	}
	
	@Test
	public void illegalUserName() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("user", "*foo")));
		
		failGetUser(REMOTE, new AuthStorageException("Illegal value stored in db: 30010 Illegal " +
				"user name: Illegal character in user name *foo: *"));
		
	}
	
	@Test
	public void missingDisplayName() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("display", "    \t \n")));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: display name"));
	}
	
	@Test
	public void illegalDisplayName() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("display", TestCommon.LONG101)));
		
		failGetUser(new UserName("foo"), new AuthStorageException("Illegal value stored in db: " +
				"30001 Illegal input parameter: display name size greater than limit 100"));
	}
	
	@Test
	public void missingEmail() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("email", "    \t \n")));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: email address"));
	}
	
	@Test
	public void illegalEmail() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("email", "noemailhere")));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30020 Illegal email address: noemailhere"));
	}
	
	@Test
	public void disabledStateMissingReason() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		
		when(mockClock.instant()).thenReturn(Instant.now());
		storage.disableAccount(new UserName("foo"), new UserName("bar"), "baz");
		
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("dsblereas", "   \t   ")));
		
		failGetUser(REMOTE, new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: Disabled reason"));
	}
	
	@Test
	public void invalidDisabledState() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		
		when(mockClock.instant()).thenReturn(Instant.now());
		storage.disableAccount(new UserName("foo"), new UserName("bar"), "baz");
		
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("dsbleadmin", null)));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: If disabledReason is present byAdmin and time " +
				"cannot be absent"));
	}
	
	@Test
	public void disabledStateLongReason() throws Exception {
		storage.createUser(new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
				new DisplayName("bar"), REMOTE, NOW, null));
		
		when(mockClock.instant()).thenReturn(Instant.now());
		storage.disableAccount(new UserName("foo"), new UserName("bar"), "baz");
		
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("dsblereas", TestCommon.LONG1001)));
		
		failGetUser(REMOTE, new AuthStorageException("Illegal value stored in db: 30001 " +
				"Illegal input parameter: Disabled reason size greater than limit 1000"));
	}
	
	private void failGetUser(final RemoteIdentityWithLocalID ri, final Exception e) {
		try {
			storage.getUser(ri);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failGetUser(final UserName name, final Exception e) {
		try {
			storage.getUser(name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
