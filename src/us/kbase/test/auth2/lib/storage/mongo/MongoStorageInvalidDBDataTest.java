package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.core.StringStartsWith.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.NewUser;
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
	
	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	@Test
	public void missingUserName() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("user", null)));
		
		failGetUser(REMOTE, new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: user name"));
	}
	
	@Test
	public void illegalUserName() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("user", "*foo")));
		
		failGetUser(REMOTE, new AuthStorageException("Illegal value stored in db: 30010 Illegal " +
				"user name: Illegal character in user name *foo: *"));
		
	}
	
	@Test
	public void missingDisplayName() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("display", "    \t \n")));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: display name"));
	}
	
	@Test
	public void illegalDisplayName() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("display", TestCommon.LONG101)));
		
		failGetUser(new UserName("foo"), new AuthStorageException("Illegal value stored in db: " +
				"30001 Illegal input parameter: display name size greater than limit 100"));
	}
	
	@Test
	public void missingEmail() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("email", "    \t \n")));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: email address"));
	}
	
	@Test
	public void illegalEmail() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("email", "noemailhere")));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30020 Illegal email address: noemailhere"));
	}
	
	@Test
	public void missingPolicyID() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE)
				.withPolicyID(new PolicyID("foo"), Instant.now()).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$addToSet", new Document("policyids", new Document("id", "       ")
						.append("agreed", new Date()))));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: policy id"));
	}
	
	@Test
	public void illegalPolicyID() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE)
				.withPolicyID(new PolicyID("foo"), Instant.now()).build());
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$addToSet", new Document("policyids", new Document("id", "foo\nbar")
						.append("agreed", new Date()))));
		
		failGetUser(new UserName("foo"), new AuthStorageException(
				"Illegal value stored in db: 30001 Illegal input parameter: " +
				"policy id contains control characters"));
	}
	
	@Test
	public void illegalTokenName() throws Exception {
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken st = StoredToken.getBuilder(
					TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now().plusSeconds(10))
				.withTokenName(new TokenName("foo")).build();
		storage.storeToken(st, t.getHashedToken().getTokenHash());
		db.getCollection("tokens").updateOne(new Document("user", "baz"),
				new Document("$set", new Document("name", "  foo\nbar  ")));
		
		try {
			storage.getToken(t.getHashedToken());
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new AuthStorageException(
					"Illegal value stored in db: 30001 Illegal input parameter: " +
					"token name contains control characters"));
		}
	}
	
	@Test
	public void illegalIPAddress() throws Exception {
		/* Some really annoying ISPs will send you to a custom search page or something
		 * when you look up a fake domain, so if InetAddress finds an address we have to abort
		 * the test.
		 */
		try {
			final InetAddress addr = InetAddress.getByName("fakeip");
			System.err.println("Buttwipe ISP detected. 'fakeip' domain was redirected to " +
					addr + ". Skipping this test; please be sure to run again on a " +
					"non-buttwipe ISP.");
			return;
		} catch (Exception e) {
			//do nothing
		}
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken st = StoredToken.getBuilder(
					TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now().plusSeconds(10))
				.build();
		storage.storeToken(st, t.getHashedToken().getTokenHash());

		db.getCollection("tokens").updateOne(new Document("user", "baz"),
				new Document("$set", new Document("ip", "fakeip")));
		
		try {
			storage.getToken(t.getHashedToken());
			fail("expected exception");
		} catch (AuthStorageException e) {
			assertThat("incorrect exception message", e.getMessage(),
					// error message from InetAddress changes based on test context
					startsWith("Illegal value stored in db: fakeip"));
		}
	}
	
	@Test
	public void missingCustomContextKey() throws Exception {
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken st = StoredToken.getBuilder(
					TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now().plusSeconds(10))
				.build();
		storage.storeToken(st, t.getHashedToken().getTokenHash());

		
		db.getCollection("tokens").updateOne(new Document("user", "baz"),
				new Document("$set", new Document("custctx", Arrays.asList(
						new Document("k", null).append("v", "thing")))));
		
		try {
			storage.getToken(t.getHashedToken());
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new AuthStorageException(
					"Illegal value stored in db: 30000 Missing input parameter: key"));
		}
	}
	
	@Test
	public void illegalCustomContextKey() throws Exception {
		final IncomingToken t = new IncomingToken("foobar");
		final StoredToken st = StoredToken.getBuilder(
					TokenType.LOGIN, UUID.randomUUID(), new UserName("baz"))
				.withLifeTime(Instant.now(), Instant.now().plusSeconds(10))
				.build();
		storage.storeToken(st, t.getHashedToken().getTokenHash());

		
		db.getCollection("tokens").updateOne(new Document("user", "baz"),
				new Document("$set", new Document("custctx", Arrays.asList(
						new Document("k", TestCommon.LONG101.substring(0, 21))
						.append("v", "thing")))));
		
		try {
			storage.getToken(t.getHashedToken());
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new AuthStorageException(
					"Illegal value stored in db: 30001 Illegal input parameter: " +
					"key size greater than limit 20"));
		}
	}
	
	@Test
	public void disabledStateMissingReason() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		when(mockClock.instant()).thenReturn(Instant.now());
		storage.disableAccount(new UserName("foo"), new UserName("bar"), "baz");
		
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("dsblereas", "   \t   ")));
		
		failGetUser(REMOTE, new AuthStorageException(
				"Illegal value stored in db: 30000 Missing input parameter: Disabled reason"));
	}
	
	@Test
	public void invalidDisabledState() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
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
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), new DisplayName("bar"), NOW, REMOTE).build());
		
		when(mockClock.instant()).thenReturn(Instant.now());
		storage.disableAccount(new UserName("foo"), new UserName("bar"), "baz");
		
		db.getCollection("users").updateOne(new Document("user", "foo"),
				new Document("$set", new Document("dsblereas", TestCommon.LONG1001)));
		
		failGetUser(REMOTE, new AuthStorageException("Illegal value stored in db: 30001 " +
				"Illegal input parameter: Disabled reason size greater than limit 1000"));
	}
	
	private void failGetUser(final RemoteIdentity ri, final Exception e) {
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
