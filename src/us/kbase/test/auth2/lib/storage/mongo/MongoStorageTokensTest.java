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
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTokensTest extends MongoStorageTester {
	
	//TODO TEST test that temporary tokens are stored in the db correctly. Only the hash is really checked.

	@Test
	public void storeAndGet() throws Exception {
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 10000).getHashedToken();
		storage.storeToken(ht);
		
		final HashedToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", ht, is(st));
	}
	
	@Test
	public void storeAndGetNoName() throws Exception {
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN, "sometoken",
				new UserName("bar"), Instant.now(), 10000).getHashedToken();
		storage.storeToken(ht);
		
		final HashedToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", ht, is(st));
	}
	
	@Test
	public void storeTokenFailNull() {
		failStoreToken(null, new NullPointerException("token"));
	}
	
	@Test
	public void storeTokenFailDuplicateID() throws Exception {
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 10000).getHashedToken();
		storage.storeToken(ht);
		final Instant now = Instant.now();
		failStoreToken(new HashedToken(ht.getId(),
				TokenType.DEV,
				Optional.of(new TokenName("bleah")), "somehash", new UserName("baz"), now, now.plusMillis(10000)),
				new IllegalArgumentException(String.format(
						"Token ID %s already exists in the database", ht.getId())));
	}
	
	@Test
	public void storeTokenFailDuplicateToken() throws Exception {
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 10000).getHashedToken();
		storage.storeToken(ht);
		final Instant now = Instant.now();
		final UUID id = UUID.randomUUID();
		failStoreToken(new HashedToken(id,
				TokenType.SERV, Optional.of(new TokenName("bleah")),
				ht.getTokenHash(), new UserName("baz"), now, now.plusMillis(10000)),
				new IllegalArgumentException(String.format(
						"Token hash for token ID %s already exists in the database", id)));
	}
	
	private void failStoreToken(final HashedToken token, final Exception e) {
		try {
			storage.storeToken(token);
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
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		Thread.sleep(1);
		storage.storeToken(ht);
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
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		final HashedToken ht2 = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"),
				"sometoken1", new UserName("bar2"), Instant.now(), 0).getHashedToken();
		final HashedToken ht3 = new NewToken(UUID.randomUUID(), TokenType.LOGIN, "sometoken3",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		storage.storeToken(ht);
		storage.storeToken(ht2);
		storage.storeToken(ht3);
		
		assertThat("incorrect tokens", storage.getTokens(new UserName("bar")), is(set(ht3, ht)));
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
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		final HashedToken ht2 = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"),
				"sometoken1", new UserName("bar"), Instant.now(), 0).getHashedToken();
		storage.storeToken(ht);
		storage.storeToken(ht2);
		storage.deleteToken(new UserName("bar"), ht.getId());
		assertThat("incorrect tokens", storage.getTokens(new UserName("bar")), is(set(ht2)));
	}
	
	@Test
	public void deleteTokenFailNulls() throws Exception {
		failDeleteToken(null, UUID.randomUUID(), new NullPointerException("userName"));
		failDeleteToken(new UserName("bar"), null, new NullPointerException("tokenId"));
	}
	
	@Test
	public void deleteTokenFailBadID() throws Exception {
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		storage.storeToken(ht);
		final UUID id = UUID.randomUUID();
		failDeleteToken(new UserName("bar"), id, new NoSuchTokenException(
				String.format("No token %s for user bar exists", id)));
	}
	
	@Test
	public void deleteTokenFailBadUser() throws Exception {
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		storage.storeToken(ht);
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
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		final HashedToken ht2 = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"),
				"sometoken1", new UserName("bar2"), Instant.now(), 0).getHashedToken();
		final HashedToken ht3 = new NewToken(UUID.randomUUID(), TokenType.LOGIN, "sometoken3",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		storage.storeToken(ht);
		storage.storeToken(ht2);
		storage.storeToken(ht3);
		
		storage.deleteTokens(new UserName("bar"));
		assertThat("tokens remaining", storage.getTokens(new UserName("bar")),
				is(Collections.emptySet()));
		
		assertThat("incorrect tokens", storage.getTokens(new UserName("bar2")), is(set(ht2)));
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
		final HashedToken ht = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"), "sometoken",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		final HashedToken ht2 = new NewToken(UUID.randomUUID(), TokenType.LOGIN,
				new TokenName("foo"),
				"sometoken1", new UserName("bar2"), Instant.now(), 0).getHashedToken();
		final HashedToken ht3 = new NewToken(UUID.randomUUID(), TokenType.LOGIN, "sometoken3",
				new UserName("bar"), Instant.now(), 0).getHashedToken();
		storage.storeToken(ht);
		storage.storeToken(ht2);
		storage.storeToken(ht3);
		
		storage.deleteTokens();
		assertThat("tokens remaining", storage.getTokens(new UserName("bar")),
				is(Collections.emptySet()));
		assertThat("tokens remaining", storage.getTokens(new UserName("bar2")),
				is(Collections.emptySet()));
	}
}
