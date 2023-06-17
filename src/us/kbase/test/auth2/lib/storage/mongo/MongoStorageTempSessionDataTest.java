package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.TemporarySessionData;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTempSessionDataTest extends MongoStorageTester {
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));
	
	@Test
	public void storeAndGetLoginStart() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final TemporarySessionData tsd = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.login("stateystate", "pkcecode");
		storage.storeTemporarySessionData(tsd, IncomingToken.hash("whoo"));
		
		assertThat("incorrect session data", storage.getTemporarySessionData(
						new IncomingToken("whoo").getHashedToken()),
				is(TemporarySessionData.create(
						id, now, now.plusSeconds(10)).login("stateystate", "pkcecode")));
	}
	
	@Test
	public void storeAndGetLoginIdents() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final TemporarySessionData tsd = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.login(set(REMOTE2));
		storage.storeTemporarySessionData(tsd, IncomingToken.hash("foobar"));
	
		assertThat("incorrect session data", storage.getTemporarySessionData(
				new IncomingToken("foobar").getHashedToken()), is(
						TemporarySessionData.create(id, now, now.plusSeconds(10))
							.login(set(REMOTE2))));
	}
	
	@Test
	public void storeAndGetLinkIdents() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final TemporarySessionData tsd = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link(new UserName("whee"), set(REMOTE1, REMOTE2));
		storage.storeTemporarySessionData(tsd, IncomingToken.hash("foobar"));
		
		assertThat("incorrect session data", storage.getTemporarySessionData(
				new IncomingToken("foobar").getHashedToken()), is(
						TemporarySessionData.create(id, now, now.plusSeconds(10))
							.link(new UserName("whee"), set(REMOTE1, REMOTE2))));
	}
	
	@Test
	public void storeAndGetLinkStart() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final TemporarySessionData tsd = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("otherstate", "pkceothercode", new UserName("whee"));
		storage.storeTemporarySessionData(tsd, IncomingToken.hash("foobar"));
		
		assertThat("incorrect session data", storage.getTemporarySessionData(
				new IncomingToken("foobar").getHashedToken()), is(
						TemporarySessionData.create(id, now, now.plusSeconds(10))
							.link("otherstate", "pkceothercode", new UserName("whee"))));
	}
	
	@Test
	public void storeAndGetError() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now().truncatedTo(ChronoUnit.MILLIS); // mongo truncates
		final TemporarySessionData tsd = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.error("foobarbaz", ErrorType.ID_ALREADY_LINKED);
		storage.storeTemporarySessionData(tsd, IncomingToken.hash("foobar"));
		
		assertThat("incorrect session data", storage.getTemporarySessionData(
				new IncomingToken("foobar").getHashedToken()), is(
						TemporarySessionData.create(id, now, now.plusSeconds(10))
							.error("foobarbaz", ErrorType.ID_ALREADY_LINKED)));
	}
	
	@Test
	public void storeTempSessionDataFailNulls() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData tsd = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee"));
		failStoreTemporarySessionData(null, "foo", new NullPointerException("data"));
		failStoreTemporarySessionData(tsd, null,
				new IllegalArgumentException("hash cannot be null or whitespace only"));
		failStoreTemporarySessionData(tsd, "   \t   \n ",
				new IllegalArgumentException("hash cannot be null or whitespace only"));
	}
	
	@Test
	public void storeTempDataFailDuplicateTokenID() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData data = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee"));
		final TemporarySessionData data2 = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee2"));
		storage.storeTemporarySessionData(data, "whee");
		failStoreTemporarySessionData(data2, "whee2", new IllegalArgumentException(
				"Temporary token ID " + id + " already exists in the database"));
	}
	
	@Test
	public void storeTempDataFailDuplicateToken() throws Exception {
		final UUID id = UUID.randomUUID();
		final UUID id2 = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData data = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee"));
		final TemporarySessionData data2 = TemporarySessionData
				.create(id2, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee2"));
		storage.storeTemporarySessionData(data, "whee");
		failStoreTemporarySessionData(data2, "whee", new IllegalArgumentException(
				"Token hash for temporary token ID " + id2 +
				" already exists in the database"));
	}
	
	private void failStoreTemporarySessionData(
			final TemporarySessionData data,
			final String hash,
			final Exception e) {
		try {
			storage.storeTemporarySessionData(data, hash);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTempDataFailNull() {
		failGetTemporaryData(null, new NullPointerException("token"));
	}
	
	@Test
	public void getTempDataFailNoSuchToken() throws Exception {
		failGetTemporaryData(new IncomingToken("foo").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void getTempDataFailExpiredToken() throws Exception {
		/* this test could not cover the intended code if mongo removes the record before the test
		 * concludes.
		 * maybe there's a way of turning token removal off temporarily?
		 * only 1 sweep / min so not very likely
		 */
		final UUID id = UUID.randomUUID();
		final TemporarySessionData data = TemporarySessionData.create(id, Instant.now(), 0)
				.link("state", "pkce", new UserName("whee"));

		storage.storeTemporarySessionData(data, IncomingToken.hash("foobar"));
		
		Thread.sleep(1);
		failGetTemporaryData(new IncomingToken("foobar").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void getTempDataFailBadUserInDB() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData tsd = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link(new UserName("foo"), set(REMOTE2));
		storage.storeTemporarySessionData(tsd, IncomingToken.hash("foobar"));
		
		db.getCollection("tempdata").updateOne(new Document("id", id.toString()),
				new Document("$set", new Document("user", null)));
		
		failGetTemporaryData(new IncomingToken("foobar").getHashedToken(),
				new AuthStorageException(
						"Illegal value stored in db: 30000 Missing input parameter: user name"));

		final UUID id2 = UUID.randomUUID();
		final TemporarySessionData tsd2 = TemporarySessionData
				.create(id2, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("foo"));
		storage.storeTemporarySessionData(tsd2, IncomingToken.hash("foobar2"));
		
		db.getCollection("tempdata").updateOne(new Document("id", id2.toString()),
				new Document("$set", new Document("user", null)));
		
		failGetTemporaryData(new IncomingToken("foobar2").getHashedToken(),
				new AuthStorageException(
						"Illegal value stored in db: 30000 Missing input parameter: user name"));
	}
	
	private void failGetTemporaryData(
			final IncomingHashedToken token,
			final Exception e) {
		try {
			storage.getTemporarySessionData(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void deleteTempDataByToken() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData data = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee"));

		storage.storeTemporarySessionData(data, IncomingToken.hash("foobar"));
		
		// check token is there
		storage.getTemporarySessionData(new IncomingToken("foobar").getHashedToken());
		
		final Optional<UUID> retid = storage.deleteTemporarySessionData(
				new IncomingToken("foobar").getHashedToken());
		
		assertThat("incorrect token id", retid, is(Optional.of(id)));
		
		failGetTemporaryData(new IncomingToken("foobar").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void deleteNonExistentTempDataByToken() throws Exception {
		final Optional<UUID> retid = storage.deleteTemporarySessionData(
				new IncomingToken("foobar").getHashedToken());
		
		assertThat("incorrect token id", retid, is(Optional.empty()));
	}
	
	@Test
	public void deleteNoTempDatasByUser() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData data = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee"));

		storage.storeTemporarySessionData(data, IncomingToken.hash("foobar"));
		// check token is there
		storage.getTemporarySessionData(new IncomingToken("foobar").getHashedToken());
		
		final long count = storage.deleteTemporarySessionData(new UserName("whoo"));
		assertThat("correct deletion count", count, is(0L));
		
		// check token is there
		storage.getTemporarySessionData(new IncomingToken("foobar").getHashedToken());
	}
	
	@Test
	public void deleteOneTempDataByUser() throws Exception {
		final UUID id = UUID.randomUUID();
		final Instant now = Instant.now();
		final TemporarySessionData data = TemporarySessionData.create(id, now, now.plusSeconds(10))
				.link("state", "pkce", new UserName("whee"));

		storage.storeTemporarySessionData(data, IncomingToken.hash("foobar"));
		// check token is there
		storage.getTemporarySessionData(new IncomingToken("foobar").getHashedToken());
		
		final long count = storage.deleteTemporarySessionData(new UserName("whee"));
		assertThat("correct deletion count", count, is(1L));
		
		failGetTemporaryData(new IncomingToken("foobar").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void deleteTwoTempDatasByUser() throws Exception {
		final Instant now = Instant.now();
		final TemporarySessionData data1 = TemporarySessionData.create(UUID.randomUUID(),
				now, now.plusSeconds(10)).link("state", "pkce", new UserName("whee"));
		final TemporarySessionData data2 = TemporarySessionData.create(UUID.randomUUID(),
				now, now.plusSeconds(10)).link(new UserName("whee"), set(REMOTE1));
		

		storage.storeTemporarySessionData(data1, IncomingToken.hash("foobar"));
		storage.storeTemporarySessionData(data2, IncomingToken.hash("foobar2"));
		// check token is there
		storage.getTemporarySessionData(new IncomingToken("foobar").getHashedToken());
		storage.getTemporarySessionData(new IncomingToken("foobar2").getHashedToken());
		
		final long count = storage.deleteTemporarySessionData(new UserName("whee"));
		assertThat("correct deletion count", count, is(2L));
		
		failGetTemporaryData(new IncomingToken("foobar").getHashedToken(),
				new NoSuchTokenException("Token not found"));
		failGetTemporaryData(new IncomingToken("foobar2").getHashedToken(),
				new NoSuchTokenException("Token not found"));
	}
	
	@Test
	public void deleteTempDataFailNull() throws Exception {
		try {
			storage.deleteTemporarySessionData((IncomingHashedToken) null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
		try {
			storage.deleteTemporarySessionData((UserName) null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("userName"));
		}
	}

}
