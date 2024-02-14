package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.bson.Document;

import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.user.NewUser;

public class MongoStorageTestCommon {
	
	private static final String RECANONICALIZATION_FLAG = "_recanonicalized_for_version_";
	
	private static final Instant NOW = Instant.now()
			.truncatedTo(ChronoUnit.MILLIS); // mongo truncates
	
	private static RemoteIdentity createRemoteIdentity(final int id) {
		return new RemoteIdentity(
				new RemoteIdentityID("prov", "bar" + id),
				new RemoteIdentityDetails("user", "full", "email")
		);
	}
	
	public static void createUser(
			final AuthStorage storage,
			final String username,
			final String displayName,
			final int remoteID)
			throws Exception {
		storage.createUser(NewUser.getBuilder(
				new UserName(username),
				UUID.randomUUID(),
				new DisplayName(displayName),
				NOW,
				createRemoteIdentity(remoteID)
		).build());
	}
	
	/** Get the flag set on users in mongoDB when their display names have been recanonicalized
	 * for a specific version.
	 * @param version The semantic version with . replaced by _.
	 * @return the flag.
	 */
	public static String getRecanonicalizationFlag(final String version) {
		return RECANONICALIZATION_FLAG + version;
	}
	
	public static void trashCanonicalizationData(final MongoDatabase db, final String username) {
		db.getCollection("users").updateOne(
				new Document("user", username),
				new Document("$set",
						new Document("dispcan", Arrays.asList("messed", "up", username)))
		);
	}
	
	public static void setRecanonicalizedFlag(
			final MongoDatabase db, final String username, final String version) {
		db.getCollection("users").updateOne(
				new Document("user", username),
				new Document("$set", new Document(getRecanonicalizationFlag(version), true))
		);
	}
	
	public static void assertNoRecanonicalizationFlag(
			final MongoDatabase db, final String username) {
		final Document user = getUserDoc(db, username);
		for (final String key: user.keySet()) {
			if (key.startsWith(RECANONICALIZATION_FLAG)) {
				fail(String.format("Found recanonicalization flag %s for user %s", key, username));
			}
		}
	}
	
	
	public static void assertOneRecanonicalizationFlag(
			final MongoDatabase db, final String username, final String version) {
		final Document user = getUserDoc(db, username);
		final Set<String> flags = user.keySet().stream()
				.filter(k -> k.startsWith(RECANONICALIZATION_FLAG)).collect(Collectors.toSet());
		assertThat("incorrect recanonicalization flags", flags,
				is(set(getRecanonicalizationFlag(version))));
	}
	
	public static Document getUserDoc(final MongoDatabase db, final String username) {
		return db.getCollection("users").find(new Document("user", username)).first();
	}
	
	public static void assertCorrectRecanonicalization(
			final MongoDatabase db,
			final String username,
			final List<String> canonicalizedName,
			final String version) {
		final String flag = getRecanonicalizationFlag(version);
		final Document user = getUserDoc(db, username);
		@SuppressWarnings("unchecked")
		final List<String> canon = (List<String>) user.get("dispcan");
		assertThat("incorrect canonicalization", canon, is(canonicalizedName));
		assertThat("missing flag", user.containsKey(flag), is(true));
		if (user.containsKey(flag)) {
			assertThat("incorrect flag value", user.getBoolean(flag), is(true));
		}
	}

}
