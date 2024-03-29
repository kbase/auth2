package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;

import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bson.Document;
import org.junit.Test;

import com.mongodb.client.FindIterable;
import com.mongodb.client.MongoCollection;
import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageStartUpTest extends MongoStorageTester {

	@Test
	public void nullConstructor() throws Exception {
		try {
			new MongoStorage(null);
			fail("expected exception");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is("db"));
		}
	}

	@Test
	public void startUpAndCheckConfigDoc() throws Exception {
		final MongoDatabase db = mc.getDatabase("startUpAndCheckConfigDoc");
		new MongoStorage(db);
		final MongoCollection<Document> col = db.getCollection("config");
		assertThat("Only one config doc", col.countDocuments(), is(1L));
		final FindIterable<Document> c = col.find();
		final Document d = c.first();

		assertThat("correct config key & value", (String)d.get("schema"), is("schema"));
		assertThat("not in update", (Boolean)d.get("inupdate"), is(false));
		assertThat("schema v1", (Integer)d.get("schemaver"), is(1));

		//check startup works with the config object in place
		final MongoStorage ms = new MongoStorage(db);
		ms.setCustomRole(new CustomRole("foo", "bar"));
		assertThat("failed basic storage operation", ms.getCustomRoles(),
				is(set(new CustomRole("foo", "bar"))));
	}

	@Test
	public void startUpWith2ConfigDocs() throws Exception {
		final MongoDatabase db = mc.getDatabase("startUpWith2ConfigDocs");

		final Document m = new Document("schema", "schema")
				.append("inupdate", false)
				.append("schemaver", 1);

		db.getCollection("config").insertMany(Arrays.asList(m,
				// need to create a new document to create a new mongo _id
				new Document(m)));

		final Pattern errorPattern = Pattern.compile(
				"Failed to create index: Write failed with error code 11000 and error message " +
				"'(exception: )?(.*)E11000 duplicate key error (index|collection): " +
				"startUpWith2ConfigDocs.config( index: |\\.\\$)schema_1\\s+dup key: " +
				"(\\{ schema: \"schema\" \\}'|\\{ : \"schema\" \\}')");
		try {
			new MongoStorage(db);
			fail("started mongo with bad config");
		} catch (StorageInitException e) {
			final Matcher match = errorPattern.matcher(e.getMessage());
			assertThat("exception did not match: \n" + e.getMessage(), match.matches(), is(true));
		}
	}

	@Test
	public void startUpWithBadSchemaVersion() throws Exception {
		final MongoDatabase db = mc.getDatabase("startUpWithBadSchemaVersion");

		final Document m = new Document("schema", "schema")
				.append("inupdate", false)
				.append("schemaver", 4);

		db.getCollection("config").insertOne(m);

		failMongoStart(db, new StorageInitException(
				"Incompatible database schema. Server is v1, DB is v4"));
	}

	@Test
	public void startUpWithUpdateInProgress() throws Exception {
		final MongoDatabase db = mc.getDatabase("startUpWithUpdateInProgress");

		final Document m = new Document("schema", "schema")
				.append("inupdate", true)
				.append("schemaver", 1);

		db.getCollection("config").insertOne(m);

		failMongoStart(db, new StorageInitException(
				"The database is in the middle of an update from v1 of the " +
				"schema. Aborting startup."));
	}

	private void failMongoStart(final MongoDatabase db, final Exception exp)
			throws Exception {
		try {
			new MongoStorage(db);
			fail("started mongo with bad config");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exp);
		}
	}

	/* The following tests ensure that all indexes are created correctly. The collection names
	 * are tested so that if a new collection is added the test will fail without altering
	 * said test, at which time the coder will hopefully read this notice and add index tests
	 * for the new collection.
	 */

	@Test
	public void checkCollectionNames() throws Exception {
		final Set<String> names = new HashSet<>();
		final Set<String> expected = set(
				"config",
				"config_app",
				"config_ext",
				"config_prov",
				"cust_roles",
				"test_cust_roles",
				"tempdata",
				"tokens",
				"test_tokens",
				"users",
				"test_users");
		if (includeSystemIndexes) {
			expected.add("system.indexes");
		}
		// this is annoying. MongoIterator has two forEach methods with different signatures
		// and so which one to call is ambiguous for lambda expressions.
		db.listCollectionNames().forEach((Consumer<String>) names::add);
		assertThat("incorrect collection names", names, is(expected));
	}

	@Test
	public void indexesConfig() {
		final Set<Document> indexes = getAndNormalizeIndexes("config");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("schema", 1))
						.append("name", "schema_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_")
				)));
	}

	@Test
	public void indexesConfigApp() {
		final Set<Document> indexes = getAndNormalizeIndexes("config_app");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("key", 1))
						.append("name", "key_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_")
				)));
	}

	@Test
	public void indexesConfigExt() {
		final Set<Document> indexes = getAndNormalizeIndexes("config_ext");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("key", 1))
						.append("name", "key_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_")
				)));
	}

	@Test
	public void indexesConfigProv() {
		final Set<Document> indexes = getAndNormalizeIndexes("config_prov");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("prov", 1).append("key", 1))
						.append("name", "prov_1_key_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_")
				)));
	}

	@Test
	public void indexesCustRoles() {
		final Set<Document> indexes = getAndNormalizeIndexes("cust_roles");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("id", 1))
						.append("name", "id_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_")
				)));
	}

	@Test
	public void indexesTestCustRoles() {
		final Set<Document> indexes = getAndNormalizeIndexes("test_cust_roles");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("id", 1))
						.append("name", "id_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_"),
				new Document("v", indexVer)
						.append("key", new Document("expires", 1))
						.append("name", "expires_1")
						.append("expireAfterSeconds", 0L)
				)));
	}

	@Test
	public void indexesTempData() {
		final Set<Document> indexes = getAndNormalizeIndexes("tempdata");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("token", 1))
						.append("name", "token_1"),
				new Document("v", indexVer)
						.append("key", new Document("expires", 1))
						.append("name", "expires_1")
						.append("expireAfterSeconds", 0L),
				new Document("v", indexVer)
						.append("sparse", true)
						.append("key", new Document("user", 1))
						.append("name", "user_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_"),
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("id", 1))
						.append("name", "id_1")
				)));
	}

	@Test
	public void indexesTokens() {
		final Set<Document> indexes = getAndNormalizeIndexes("tokens");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("token", 1))
						.append("name", "token_1"),
				new Document("v", indexVer)
						.append("key", new Document("expires", 1))
						.append("name", "expires_1")
						.append("expireAfterSeconds", 0L),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_"),
				new Document("v", indexVer)
						.append("key", new Document("user", 1))
						.append("name", "user_1"),
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("id", 1))
						.append("name", "id_1")
				)));
	}

	@Test
	public void indexesTestTokens() {
		final Set<Document> indexes = getAndNormalizeIndexes("test_tokens");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("token", 1))
						.append("name", "token_1"),
				new Document("v", indexVer)
						.append("key", new Document("expires", 1))
						.append("name", "expires_1")
						.append("expireAfterSeconds", 0L),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_"),
				new Document("v", indexVer)
						.append("key", new Document("user", 1))
						.append("name", "user_1"),
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("id", 1))
						.append("name", "id_1")
				)));
	}

	@Test
	public void indexesUsers() {
		final Set<Document> indexes = getAndNormalizeIndexes("users");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("key", new Document("custrls", 1))
						.append("name", "custrls_1")
						.append("sparse", true),
				new Document("v", indexVer)
						.append("key", new Document("dispcan", 1))
						.append("name", "dispcan_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_"),
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("idents.id", 1))
						.append("name", "idents.id_1")
						.append("sparse", true),
				new Document("v", indexVer)
						.append("key", new Document("roles", 1))
						.append("name", "roles_1")
						.append("sparse", true),
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("user", 1))
						.append("name", "user_1"),
				new Document("v", indexVer)
						.append("key", new Document("anonid", 1))
						.append("name", "anonid_1")
						.append("sparse", true)
				)));
	}

	@Test
	public void indexesTestUsers() {
		final Set<Document> indexes = getAndNormalizeIndexes("test_users");
		assertThat("incorrect indexes", indexes, is(set(
				new Document("v", indexVer)
						.append("key", new Document("custrls", 1))
						.append("name", "custrls_1")
						.append("sparse", true),
				new Document("v", indexVer)
						.append("key", new Document("dispcan", 1))
						.append("name", "dispcan_1"),
				new Document("v", indexVer)
						.append("key", new Document("_id", 1))
						.append("name", "_id_"),
				new Document("v", indexVer)
						.append("key", new Document("roles", 1))
						.append("name", "roles_1")
						.append("sparse", true),
				new Document("v", indexVer)
						.append("unique", true)
						.append("key", new Document("user", 1))
						.append("name", "user_1"),
				new Document("v", indexVer)
						.append("key", new Document("expires", 1))
						.append("name", "expires_1")
						.append("expireAfterSeconds", 0L)
				)));
	}

	private Set<Document> getAndNormalizeIndexes(final String collectionName) {
		final Set<Document> indexes = new HashSet<>();
		for (Document index: db.getCollection(collectionName).listIndexes()) {
			// In MongoDB 4.4, the listIndexes and the mongo shell helper method db.collection.getIndexes()
			// no longer returns the namespace ns field in the index specification documents.
			index.remove("ns");
			// some versions of Mongo return ints, some longs. Convert all to longs.
			if (index.containsKey("expireAfterSeconds")) {
				index.put("expireAfterSeconds", ((Number) index.get("expireAfterSeconds")).longValue());
			}
			indexes.add(index);
		}
		return indexes;
	}
}
