package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTestTokensTest extends MongoStorageTester {
	
	@Test
	public void storeAndGet() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final StoredToken store = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(20))
			.withContext(TokenCreationContext.getBuilder()
					.withNullableAgent("a", "av")
					.withNullableOS("o", "oa")
					.withNullableDevice("d")
					.withIpAddress(InetAddress.getByName("1.1.1.2"))
					.withCustomContext("k1", "v1")
					.withCustomContext("k2", "v2")
					.build())
			.withTokenName(new TokenName("foo")).build();
		storage.testModeStoreToken(store, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
		final StoredToken expected  = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(20))
			.withContext(TokenCreationContext.getBuilder()
					.withNullableAgent("a", "av")
					.withNullableOS("o", "oa")
					.withNullableDevice("d")
					.withIpAddress(InetAddress.getByName("1.1.1.2"))
					.withCustomContext("k1", "v1")
					.withCustomContext("k2", "v2")
					.build())
			.withTokenName(new TokenName("foo")).build();
		final StoredToken st = storage.testModeGetToken(
				new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeAndGetWithLocalhost() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final StoredToken store = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(20))
			.withContext(TokenCreationContext.getBuilder()
					.withIpAddress(InetAddress.getByName("localhost"))
					.build())
			.withTokenName(new TokenName("foo")).build();
		storage.testModeStoreToken(store, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
		final StoredToken expected  = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(20))
			.withContext(TokenCreationContext.getBuilder()
					.withIpAddress(InetAddress.getByName("127.0.0.1"))
					.build())
			.withTokenName(new TokenName("foo")).build();
		final StoredToken st = storage.testModeGetToken(
				new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeAndGetNoNameNoContext() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();
		storage.testModeStoreToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");

		
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();

		final StoredToken st = storage.testModeGetToken(
				new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void getWithNullCustomContext() throws Exception {
		/* Tests backwards compatibility with old tokens that don't have a custom context list
		 * in the db.
		 */
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();
		storage.testModeStoreToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
		db.getCollection("tokens").updateOne(new Document("id", id.toString()),
				new Document("$set", new Document("custctx", null)));
		
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();

		final StoredToken st = storage.testModeGetToken(
				new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeTokenFailNull() throws Exception {
		final StoredToken st = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		failStoreToken(null, "foo", new NullPointerException("token"));
		failStoreToken(
				st, null, new IllegalArgumentException("hash cannot be null or whitespace only"));
		failStoreToken(st, "   \t  ", new IllegalArgumentException(
				"hash cannot be null or whitespace only"));
	}
	
	@Test
	public void storeTokenFailDuplicateID() throws Exception {
		final Instant now = Instant.now();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		storage.testModeStoreToken(ht, "somehash");
		failStoreToken(StoredToken.getBuilder(TokenType.DEV, ht.getId(), new UserName("baz"))
				.withLifeTime(now, now.plusMillis(10000))
				.withTokenName(new TokenName("bleah")).build(),
				"someotherhash",
				new IllegalArgumentException(String.format(
						"Token ID %s already exists in the database", ht.getId())));
	}
	
	@Test
	public void storeTokenFailDuplicateToken() throws Exception {
		final Instant now = Instant.now();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		storage.testModeStoreToken(ht, "hashyhash");
		final UUID id = UUID.randomUUID();
		failStoreToken(
				StoredToken.getBuilder(TokenType.SERV, id, new UserName("baz"))
				.withLifeTime(now, now.plusMillis(10000))
				.withTokenName(new TokenName("bleah")).build(),
				"hashyhash",
				new IllegalArgumentException(String.format(
						"Token hash for token ID %s already exists in the database", id)));
	}
	
	private void failStoreToken(final StoredToken token, final String hash, final Exception e) {
		try {
			storage.testModeStoreToken(token, hash);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokenFailNull() throws Exception {
		failGetToken(null, new NullPointerException("token"));
	}
	
	@Test
	public void getTokenFailNoSuchToken() throws Exception {
		failGetToken(new IncomingToken("foo").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void getTokenFailExpired() throws Exception {
		// this test could fail to cover the intended code if mongo happens to remove the token
		// before the get occurs.
		// since the removal thread only runs 1/min should be rare.
		final Instant now = Instant.now();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, now).build();
		Thread.sleep(1);
		storage.testModeStoreToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		failGetToken(new IncomingToken("sometoken").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	private void failGetToken(final IncomingHashedToken token, final Exception e) {
		try {
			storage.testModeGetToken(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokenFromTestCollectionFail() throws Exception {
		// test that attempting to get a normal token from the test collection fails.
		final Instant now = Instant.now();
		final IncomingToken token = new IncomingToken("this is a token");
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		storage.storeToken(ht, token.getHashedToken().getTokenHash());
		
		// check the token is in the db
		storage.getToken(token.getHashedToken());
		
		failGetToken(token.getHashedToken(), new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void getTestTokenFromStdCollectionFail() throws Exception {
		// test that attempting to get a normal token from the test collection fails.
		final Instant now = Instant.now();
		final IncomingToken token = new IncomingToken("this is a token");
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		storage.testModeStoreToken(ht, token.getHashedToken().getTokenHash());
		
		// check the token is in the db
		storage.testModeGetToken(token.getHashedToken());
		
		try {
			storage.getToken(token.getHashedToken());
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NoSuchTokenException("Token not found"));
		}
	}
}
