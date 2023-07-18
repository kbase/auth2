package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.TestCommon.assertExceptionCorrect;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.bson.Document;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.auth2.lib.user.LocalUser;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageAnonymousIDTest extends MongoStorageTester {
	
	/*
	 * These tests check the lazy backfilling mechanism for anonymous user IDs added in
	 * 0.6.0. Since test users are ephemeral and only last one hour, they are not tested as
	 * all newly created users will have anonymous IDs.
	 */
	
	private static final UUID UID = UUID.randomUUID();
	private static final UUID UID2 = UUID.randomUUID();
	private static final UUID UID3 = UUID.randomUUID();
	
	private static final Instant NOW = Instant.now()
			.truncatedTo(ChronoUnit.MILLIS); // mongo truncates
	
	private static final RemoteIdentity REMOTE1 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar1"),
			new RemoteIdentityDetails("user1", "full1", "email1"));
	
	private static final RemoteIdentity REMOTE2 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar2"),
			new RemoteIdentityDetails("user2", "full2", "email2"));
	
	
	private static final RemoteIdentity REMOTE3 = new RemoteIdentity(
			new RemoteIdentityID("prov", "bar3"),
			new RemoteIdentityDetails("user3", "full3", "email3"));
	
	@Test
	public void backfillMissingAnonIDNoFieldLocalUser() throws Exception {
		backfillMissingAnonIDLocalUser(new Document("$unset", new Document("anonid", "")));
	}
		
	@Test
	public void backfillMissingAnonIDWithFieldLocalUser() throws Exception {
		backfillMissingAnonIDLocalUser(new Document("$set", new Document("anonid", null)));
	}

	private void backfillMissingAnonIDLocalUser(final Document update) throws Exception {
		final byte[] pwd = "foobarbaz2".getBytes(StandardCharsets.UTF_8);
		final byte[] salt = "whee".getBytes(StandardCharsets.UTF_8);
		final LocalUser nlu = LocalUser.getLocalUserBuilder(
				new UserName("local"), UID, new DisplayName("bar"), NOW)
				.build();
				
		storage.createLocalUser(nlu, new PasswordHashAndSalt(pwd, salt));
		db.getCollection("users").updateOne(new Document("user", "local"), update);
		
		final UUID uid2 = UUID.randomUUID();
		when(manager.mockRand.randomUUID()).thenReturn(uid2, (UUID) null);
		
		assertThat("incorrect user", storage.getLocalUser(new UserName("local")),
				is(LocalUser.getLocalUserBuilder(
						new UserName("local"), uid2, new DisplayName("bar"), NOW).build()));
	}
	
	@Test
	public void backfillMissingAnonIDNoFieldStdUser() throws Exception {
		backfillMissingAnonIDStdUser(new Document("$unset", new Document("anonid", "")));
	}
	
	@Test
	public void backFillMissingAnonIDWithFieldStdUser() throws Exception {
		backfillMissingAnonIDStdUser(new Document("$set", new Document("anonid", null)));
	}

	private void backfillMissingAnonIDStdUser(final Document update) throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("d"), NOW, REMOTE1).build());
		db.getCollection("users").updateOne(new Document("user", "foo"), update);
		
		final UUID uid2 = UUID.randomUUID();
		when(manager.mockRand.randomUUID()).thenReturn(uid2, (UUID) null);
		
		final AuthUser got = storage.getUser(new UserName("foo"));
		final AuthUser expected = AuthUser.getBuilder(
				new UserName("foo"), uid2, new DisplayName("d"), NOW)
				.withIdentity(REMOTE1)
				.build();
		assertThat("incorrect user", got, is(expected));
	}
	
	/*
	 * The following tests test race conditions by accessing the internal update method
	 * directly. At this point the userdoc has already been pulled from the database and
	 * checked for the absence of an anonymous ID, and so race conditions are possible if
	 * the document is then updated by another thread.
	 */
	
	private Method getAnonIDUpdateMethod() throws Exception {
		final Method m = MongoStorage.class
				.getDeclaredMethod("updateUserAnonID", String.class, UserName.class);
		m.setAccessible(true);
		return m;
	}
	
	@Test
	public void updateUserAnonIDWithRaceOnUpdate() throws Exception {
		/* Tests the case where the user doc is pulled from the DB and then another process
		 * adds the anonID. The next update (e.g. this one) should then be ignored.
		 */
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("d"), NOW, REMOTE1).build());
		/* We create the user with an anonymous ID to simulate the case where the userdoc was
		 * pulled from the DB and then another process added the anonymous ID.
		 */
		when(manager.mockRand.randomUUID()).thenReturn(UUID.randomUUID(), (UUID) null);
		
		final Document userdoc = (Document) getAnonIDUpdateMethod()
				.invoke(storage, "users", new UserName("foo"));
		
		// only check a few properties, the methods above test exhaustively
		assertThat("incorrect user", userdoc.getString("user"), is("foo"));
		assertThat("incorrect anonid", userdoc.getString("anonid"), is(UID.toString()));
		assertThat("incorrect dispname", userdoc.getString("display"), is("d"));
		@SuppressWarnings("unchecked")
		final List<Document> idents = (List<Document>) userdoc.get("idents");
		assertThat("incorrect prov user id", idents.get(0).get("prov_id"), is("bar1"));
	}
	
	@Test
	public void updateUserAnonWithMissingDocument() throws Exception {
		/* Tests the case where the user doc is removed after being pulled from the db.
		 * This should never happen under normal operating conditions since user cannot be
		 * removed, only disabled.
		 */
		
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("d"), NOW, REMOTE1).build());
		// We create a user with a different name to simulate removal of the target userdoc.
		when(manager.mockRand.randomUUID()).thenReturn(UUID.randomUUID(), (UUID) null);
		
		try {
			getAnonIDUpdateMethod().invoke(storage, "users", new UserName("bar"));
			fail("expected exception");
		} catch (InvocationTargetException e) {
			assertExceptionCorrect(e.getCause(), new RuntimeException(
					"User unexpectedly not found in database: bar"));
		}
	}
	
	/*
	 * Standard anon ID tests for anon ID specific methods
	 */
	
	@Test
	public void getUserNameByAnonymousIDEmptyInputSet() throws Exception {
		getUserNameByAnonymousIDSetUp();
		assertThat(
				"incorrect users",
				storage.getUserNamesFromAnonymousIDs(set()),
				is(Collections.emptyMap())
		);
	}
	
	@Test
	public void getUserNameByAnonymousIDEmptyResultSet() throws Exception {
		getUserNameByAnonymousIDSetUp();
		assertThat(
				"incorrect users",
				storage.getUserNamesFromAnonymousIDs(set(UUID.randomUUID(), UUID.randomUUID())),
				is(Collections.emptyMap())
		);
	}
	
	@Test
	public void getUserNameByAnonymousIDFullSet() throws Exception {
		getUserNameByAnonymousIDSetUp();
		assertThat(
				"incorrect users",
				storage.getUserNamesFromAnonymousIDs(set(UID2, UUID.randomUUID(), UID, UID3)),
				is(ImmutableMap.of(UID, new UserName("foo"), UID2, new UserName("foo2")))
		);
	}

	private void getUserNameByAnonymousIDSetUp() throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName("foo"), UID, new DisplayName("d"), NOW, REMOTE1).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("foo2"), UID2, new DisplayName("d2"), NOW, REMOTE2).build());
		storage.createUser(NewUser.getBuilder(
				new UserName("foo3"), UID3, new DisplayName("d3"), NOW, REMOTE3).build());
		// TODO CODE should pass in the time, not generate it in the DB.
		//           remove clock entirely from DB.
		when(manager.mockClock.instant()).thenReturn(NOW);
		storage.disableAccount(new UserName("foo3"), new UserName("admin"), "He gave me a wedgie");
	}
	
	@Test
	public void getUserNameByAnonymousIDFailNulls() throws Exception {
		getUserNameByAnonymousIDFail(null, new NullPointerException("anonymousIDs"));
		getUserNameByAnonymousIDFail(set(UUID.randomUUID(), null), new NullPointerException(
				"Null ID in anonymousIDs set"));
	}
	
	private void getUserNameByAnonymousIDFail(
			final Set<UUID> anonymousIDs,
			final Exception expected) {
		try {
			storage.getUserNamesFromAnonymousIDs(anonymousIDs);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
}
