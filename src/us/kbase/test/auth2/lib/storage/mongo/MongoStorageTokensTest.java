package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTokensTest extends MongoStorageTester {

	@Test
	public void storeAndGet() throws Exception {
		final HashedToken ht = new NewToken(TokenType.LOGIN, "foo", "sometoken",
				new UserName("bar"), 10000).getHashedToken();
		storage.storeToken(ht);
		
		final HashedToken st = storage.getToken(new IncomingToken("sometoken").getHashedToken());
		assertThat("incorrect token", ht, is(st));
	}
	
	@Test
	public void storeAndGetNoName() throws Exception {
		final HashedToken ht = new NewToken(TokenType.LOGIN, "sometoken",
				new UserName("bar"), 10000).getHashedToken();
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
		final HashedToken ht = new NewToken(TokenType.LOGIN, "foo", "sometoken",
				new UserName("bar"), 10000).getHashedToken();
		storage.storeToken(ht);
		final Date now = new Date();
		failStoreToken(new HashedToken(TokenType.EXTENDED_LIFETIME, "bleah", ht.getId(),
				"somehash", new UserName("baz"), now, new Date(now.getTime() + 10000)),
				new IllegalArgumentException(String.format(
						"Token ID %s already exists in the database", ht.getId())));
	}
	
	@Test
	public void storeTokenFailDuplicateToken() throws Exception {
		final HashedToken ht = new NewToken(TokenType.LOGIN, "foo", "sometoken",
				new UserName("bar"), 10000).getHashedToken();
		storage.storeToken(ht);
		final Date now = new Date();
		final UUID id = UUID.randomUUID();
		failStoreToken(new HashedToken(TokenType.EXTENDED_LIFETIME, "bleah", id,
				ht.getTokenHash(), new UserName("baz"), now, new Date(now.getTime() + 10000)),
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
		final HashedToken ht = new NewToken(TokenType.LOGIN, "foo", "sometoken",
				new UserName("bar"), 0).getHashedToken();
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

	/* TODO:
	 * all error conditions
	 * getTokens()
	 * deleteToken 3 methods
	 */
	
}
