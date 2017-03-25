package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.TokenName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTokensTest extends MongoStorageTester {
	
	//TODO TEST test that temporary tokens are stored in the db correctly. Only the hash is really checked.
	//TODO NOW make newtoken wrap stored token
	//TODO NOW builder for StoredToken

	@Test
	public void storeAndGet() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final StoredToken ht = new StoredToken(id, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 20000));
		storage.storeToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
		final StoredToken expected = new StoredToken(id, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 
						20000));
		
		final StoredToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeAndGetNoName() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final StoredToken ht = new StoredToken(id, TokenType.LOGIN, null,
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		storage.storeToken(ht, "nJKFR6Xc4vzCeI3jT+FjlC9k5Q/qVw0zd0gi1erL8ew=");
		
		final StoredToken expected = new StoredToken(id, TokenType.LOGIN, Optional.absent(),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000)); 
		
		final StoredToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", st, is(expected));
	}
	
	@Test
	public void storeTokenFailNull() throws Exception {
		final StoredToken st = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				null, new UserName("bar"), Instant.now(), Instant.now());
		failStoreToken(null, "foo", new NullPointerException("token"));
		failStoreToken(st, null, new IllegalArgumentException("Missing argument: hash"));
		failStoreToken(st, "   \t  ", new IllegalArgumentException(
				"Missing argument: hash"));
	}
	
	@Test
	public void storeTokenFailDuplicateID() throws Exception {
		final Instant now = Instant.now();
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		storage.storeToken(ht, "somehash");
		failStoreToken(new StoredToken(ht.getId(), TokenType.DEV,
				Optional.of(new TokenName("bleah")), new UserName("baz"), now,
				now.plusMillis(10000)),
				"someotherhash",
				new IllegalArgumentException(String.format(
						"Token ID %s already exists in the database", ht.getId())));
	}
	
	@Test
	public void storeTokenFailDuplicateToken() throws Exception {
		final Instant now = Instant.now();
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		storage.storeToken(ht, "hashyhash");
		final UUID id = UUID.randomUUID();
		failStoreToken(new StoredToken(id, TokenType.SERV, Optional.of(new TokenName("bleah")),
				new UserName("baz"), now, now.plusMillis(10000)), "hashyhash",
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
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("bar"), now, now);
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
		final StoredToken ht = new StoredToken(id1, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() +  15000));
		final StoredToken ht2 = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")), new UserName("bar2"), Instant.now(),
				Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		final StoredToken ht3 = new StoredToken(id3, TokenType.LOGIN, null,
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 30000));
		storage.storeToken(ht, "1");
		storage.storeToken(ht2, "2");
		storage.storeToken(ht3, "3");
		
		final StoredToken expected1 = new StoredToken(id1, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 15000));
		final StoredToken expected3 = new StoredToken(id3, TokenType.LOGIN,
				null, new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 30000));
		
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
		
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		final StoredToken ht2 = new StoredToken(id, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		storage.storeToken(ht, "1");
		storage.storeToken(ht2, "2");
		storage.deleteToken(new UserName("bar"), ht.getId());
		
		final StoredToken expected = new StoredToken(id, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		
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
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		storage.storeToken(ht, "hash");
		final UUID id = UUID.randomUUID();
		failDeleteToken(new UserName("bar"), id, new NoSuchTokenException(
				String.format("No token %s for user bar exists", id)));
	}
	
	@Test
	public void deleteTokenFailBadUser() throws Exception {
		final Instant now = Instant.now();
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
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
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 10000));
		final StoredToken ht2 = new StoredToken(id, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar2"), now, Instant.ofEpochMilli(now.toEpochMilli() + 5000));
		final StoredToken ht3 = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 100000));
		storage.storeToken(ht, "1");
		storage.storeToken(ht2, "2");
		storage.storeToken(ht3, "3");
		
		final StoredToken expected = new StoredToken(id, TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar2"), now, Instant.ofEpochMilli(now.toEpochMilli() + 5000));
		
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
		final StoredToken ht = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 100000));
		final StoredToken ht2 = new StoredToken(UUID.randomUUID(), TokenType.LOGIN,
				Optional.of(new TokenName("foo")),
				new UserName("bar2"), now, Instant.ofEpochMilli(now.toEpochMilli() + 100000));
		final StoredToken ht3 = new StoredToken(UUID.randomUUID(), TokenType.LOGIN, null,
				new UserName("bar"), now, Instant.ofEpochMilli(now.toEpochMilli() + 100000));
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
