package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.net.InetAddress;
import java.time.Instant;
import java.util.Collections;
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

public class MongoStorageTokensTest extends MongoStorageTester {
	
	@Test
	public void storeAndGet() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
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
		storage.storeToken(store, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
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
		final StoredToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeAndGetWithLocalhost() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final StoredToken store = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(20))
			.withContext(TokenCreationContext.getBuilder()
					.withIpAddress(InetAddress.getByName("localhost"))
					.build())
			.withTokenName(new TokenName("foo")).build();
		storage.storeToken(store, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
		final StoredToken expected  = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(20))
			.withContext(TokenCreationContext.getBuilder()
					.withIpAddress(InetAddress.getByName("127.0.0.1"))
					.build())
			.withTokenName(new TokenName("foo")).build();
		final StoredToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeAndGetNoNameNoContext() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();
		storage.storeToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");

		
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();

		final StoredToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void getWithNullCustomContext() throws Exception {
		/* Tests backwards compatibility with old tokens that don't have a custom context list
		 * in the db.
		 */
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();
		storage.storeToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
		db.getCollection("tokens").updateOne(new Document("id", id.toString()),
				new Document("$set", new Document("custctx", null)));
		
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build();

		final StoredToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeTokenFailNull() throws Exception {
		final StoredToken st = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(Instant.now(), Instant.now()).build();
		failStoreToken(null, "foo", new NullPointerException("token"));
		failStoreToken(st, null, new IllegalArgumentException("Missing argument: hash"));
		failStoreToken(st, "   \t  ", new IllegalArgumentException(
				"Missing argument: hash"));
	}
	
	@Test
	public void storeTokenFailDuplicateID() throws Exception {
		final Instant now = Instant.now();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		storage.storeToken(ht, "somehash");
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
		storage.storeToken(ht, "hashyhash");
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
			storage.storeToken(token, hash);
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
		storage.storeToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		failGetToken(new IncomingToken("sometoken").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	private void failGetToken(final IncomingHashedToken token, final Exception e) {
		try {
			storage.getToken(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokens() throws Exception {
		final UUID id1 = UUID.randomUUID();
		final UUID id3 = UUID.randomUUID();
		final Instant now = Instant.now();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, id1, new UserName("bar"))
				.withLifeTime(now, 15000).withTokenName(new TokenName("foo")).build();
		
		final StoredToken ht2 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar2"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		
		final StoredToken ht3 = StoredToken.getBuilder(
				TokenType.LOGIN, id3, new UserName("bar"))
				.withLifeTime(now, 30000).build();
		
		storage.storeToken(ht, "1");
		storage.storeToken(ht2, "2");
		storage.storeToken(ht3, "3");
		
		final StoredToken expected1 = StoredToken.getBuilder(
				TokenType.LOGIN, id1, new UserName("bar"))
				.withLifeTime(now, now.plusMillis(15000))
				.withTokenName(new TokenName("foo")).build();
		
		final StoredToken expected3 = StoredToken.getBuilder(
				TokenType.LOGIN, id3, new UserName("bar"))
				.withLifeTime(now, now.plusMillis(30000)).build();
		
		
		assertThat("incorrect tokens", storage.getTokens(new UserName("bar")),
				is(set(expected3, expected1)));
	}
	
	@Test
	public void getTokensFail() throws Exception {
		try {
			storage.getTokens(null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("userName"));
		}
	}
	
	@Test
	public void deleteToken() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		
		final StoredToken ht2 = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		
		storage.storeToken(ht, "1");
		storage.storeToken(ht2, "2");
		storage.deleteToken(new UserName("bar"), ht.getId());
		
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		
		assertThat("incorrect tokens", storage.getTokens(new UserName("bar")), is(set(expected)));
	}
	
	@Test
	public void deleteTokenFailNulls() throws Exception {
		failDeleteToken(null, UUID.randomUUID(), new NullPointerException("userName"));
		failDeleteToken(new UserName("bar"), null, new NullPointerException("tokenId"));
	}
	
	@Test
	public void deleteTokenFailBadID() throws Exception {
		final Instant now = Instant.now();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		
		storage.storeToken(ht, "hash");
		final UUID id = UUID.randomUUID();
		failDeleteToken(new UserName("bar"), id, new NoSuchTokenException(
				String.format("No token %s for user bar exists", id)));
	}
	
	@Test
	public void deleteTokenFailBadUser() throws Exception {
		final Instant now = Instant.now();
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();
		
		storage.storeToken(ht, "hash");
		failDeleteToken(new UserName("bar1"), ht.getId(), new NoSuchTokenException(
				String.format("No token %s for user bar1 exists", ht.getId())));
	}
	
	private void failDeleteToken(final UserName name, final UUID id, final Exception e) {
		try {
			storage.deleteToken(name, id);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void deleteTokensForUser() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 10000).withTokenName(new TokenName("foo")).build();

		final StoredToken ht2 = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar2"))
				.withLifeTime(now, 5000).withTokenName(new TokenName("foo")).build();

		final StoredToken ht3 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 100000).build();
		
		storage.storeToken(ht, "1");
		storage.storeToken(ht2, "2");
		storage.storeToken(ht3, "3");
		
		final StoredToken expected = StoredToken.getBuilder(
				TokenType.LOGIN, id, new UserName("bar2"))
				.withLifeTime(now, 5000).withTokenName(new TokenName("foo")).build();
		
		storage.deleteTokens(new UserName("bar"));
		assertThat("tokens remaining", storage.getTokens(new UserName("bar")),
				is(Collections.emptySet()));
		
		assertThat("incorrect tokens", storage.getTokens(new UserName("bar2")), is(set(expected)));
	}
	
	@Test
	public void deleteTokensForUserFail() throws Exception {
		try {
			storage.deleteTokens(null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("userName"));
		}
	}
	
	@Test
	public void deleteTokens() throws Exception {
		final Instant now = Instant.now();
		
		final StoredToken ht = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 100000).withTokenName(new TokenName("foo")).build();

		final StoredToken ht2 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar2"))
				.withLifeTime(now, 100000).withTokenName(new TokenName("foo")).build();

		final StoredToken ht3 = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
				.withLifeTime(now, 100000).build();
		
		storage.storeToken(ht, "1");
		storage.storeToken(ht2, "2");
		storage.storeToken(ht3, "3");
		
		storage.deleteTokens();
		assertThat("tokens remaining", storage.getTokens(new UserName("bar")),
				is(Collections.emptySet()));
		assertThat("tokens remaining", storage.getTokens(new UserName("bar2")),
				is(Collections.emptySet()));
	}
}
