package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.set;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.Set;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TemporaryHashedToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTempIdentitiesTest extends MongoStorageTester {
	
	private static final RemoteIdentityWithLocalID REMOTE1 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715d8"),
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentityWithLocalID REMOTE2 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891d56715d8"),
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));
	
	@Test
	public void storeAndGetEmpty() throws Exception {
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 10000).getHashedToken();;
		storage.storeIdentitiesTemporarily(tt, Collections.emptySet());
		
		assertThat("incorrect identities", storage.getTemporaryIdentities(
				new IncomingToken("foobar").getHashedToken()), is(Collections.emptySet()));
	}
	
	@Test
	public void storeAndGet1() throws Exception {
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 10000).getHashedToken();;
		storage.storeIdentitiesTemporarily(tt, set(REMOTE2));
		
		assertThat("incorrect identities", storage.getTemporaryIdentities(
				new IncomingToken("foobar").getHashedToken()), is(set(REMOTE2)));
	}
	
	@Test
	public void storeAndGet2() throws Exception {
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 10000).getHashedToken();;
		storage.storeIdentitiesTemporarily(tt, set(REMOTE2, REMOTE1));
		
		assertThat("incorrect identities", storage.getTemporaryIdentities(
				new IncomingToken("foobar").getHashedToken()), is(set(REMOTE2, REMOTE1)));
	}
	
	@Test
	public void storeTempIDFailNulls() {
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 10000).getHashedToken();
		failStoreTemporaryIdentity(null, Collections.emptySet(),
				new NullPointerException("token"));
		failStoreTemporaryIdentity(tt, null, new NullPointerException("identitySet"));
		failStoreTemporaryIdentity(tt, set(REMOTE1, null),
				new NullPointerException("Null value in identitySet"));
	}
	
	@Test
	public void storeTempIDFailDuplicateTokenID() throws Exception {
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 10000).getHashedToken();
		final TemporaryHashedToken tt2 = new TemporaryToken("foobar2", 10000).getHashedToken();
		final Field id = tt2.getClass().getDeclaredField("id");
		id.setAccessible(true);
		id.set(tt2, tt.getId());
		
		storage.storeIdentitiesTemporarily(tt, set(REMOTE1));
		failStoreTemporaryIdentity(tt2, set(REMOTE1), new IllegalArgumentException(
				"Temporary token ID " + tt2.getId() + " already exists in the database"));
	}
	
	@Test
	public void storeTempIDFailDuplicateToken() throws Exception {
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 10000).getHashedToken();
		final TemporaryHashedToken tt2 = new TemporaryToken("foobar", 10000).getHashedToken();
		
		storage.storeIdentitiesTemporarily(tt, set(REMOTE1));
		failStoreTemporaryIdentity(tt2, set(REMOTE1), new IllegalArgumentException(
				"Token hash for temporary token ID " + tt2.getId() +
				" already exists in the database"));
	}
	
	private void failStoreTemporaryIdentity(
			final TemporaryHashedToken token,
			final Set<RemoteIdentityWithLocalID> ids,
			final Exception e) {
		try {
			storage.storeIdentitiesTemporarily(token, ids);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTempIDFailNull() {
		failGetTemporaryIdentity(null, new NullPointerException("token"));
	}
	
	@Test
	public void getTempIDFailNoSuchToken() throws Exception {
		failGetTemporaryIdentity(new IncomingToken("foo").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void getTempIDFailExpiredToken() throws Exception {
		/* this test could not cover the intended code if mongo removes the record before the test
		 * concludes.
		 * maybe there's a way of turning token removal off temporarily?
		 * only 1 sweep / min so not very likely
		 */
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 0).getHashedToken();
		storage.storeIdentitiesTemporarily(tt, Collections.emptySet());
		Thread.sleep(1);
		failGetTemporaryIdentity(new IncomingToken("foobar").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void getTempIDFailBadDBData() throws Exception {
		final TemporaryHashedToken tt = new TemporaryToken("foobar", 10000).getHashedToken();
		storage.storeIdentitiesTemporarily(tt, Collections.emptySet());
		db.getCollection("temptokens").updateOne(new Document("id", tt.getId().toString()),
				new Document("$set", new Document("idents", null)));
		failGetTemporaryIdentity(new IncomingToken("foobar").getHashedToken(),
				new AuthStorageException(String.format(
						"Temporary token %s has no associated IDs field", tt.getId())));
	}
	
	private void failGetTemporaryIdentity(
			final IncomingHashedToken token,
			final Exception e) {
		try {
			storage.getTemporaryIdentities(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
