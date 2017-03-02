package us.kbase.test.auth2.lib.storage.mongo;

import org.bson.Document;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import com.github.zafarkhaja.semver.Version;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.common.test.controllers.mongo.MongoController;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTester {

	static MongoController mongo;
	static MongoClient mc;
	static MongoDatabase db;
	static MongoStorage storage;
	static Version mongoDBVer;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		mongo = new MongoController(TestCommon.getMongoExe().toString(),
				TestCommon.getTempDir(),
				TestCommon.useWiredTigerEngine());
		System.out.println(String.format("Testing against mongo excutable %s on port %s",
				TestCommon.getMongoExe(), mongo.getServerPort()));
		mc = new MongoClient("localhost:" + mongo.getServerPort());
		db = mc.getDatabase("test_mongostorage");
		storage = new MongoStorage(db);
		
		final Document bi = db.runCommand(new Document("buildinfo", 1));
		final String version = bi.getString("version");
		mongoDBVer = Version.valueOf(version);
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		if (mc != null) {
			mc.close();
		}
		if (mongo != null) {
			mongo.destroy(TestCommon.isDeleteTempFiles());
		}
	}
	
	@Before
	public void clearDB() throws Exception {
		TestCommon.destroyDB(db);
	}
}
