package us.kbase.test.auth2.lib.storage.mongo;

import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.time.Clock;

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
	static Clock mockClock;
	static Version mongoDBVer;
	static int indexVer;
	
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
		mockClock = mock(Clock.class);
		final Constructor<MongoStorage> con = MongoStorage.class.getDeclaredConstructor(
				MongoDatabase.class, Clock.class);
		con.setAccessible(true);
		storage = con.newInstance(db, mockClock);
		
		final Document bi = db.runCommand(new Document("buildinfo", 1));
		final String version = bi.getString("version");
		mongoDBVer = Version.valueOf(version);
		indexVer = mongoDBVer.greaterThanOrEqualTo(Version.forIntegers(3, 4)) ? 2 : 1;
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		if (mc != null) {
			mc.close();
		}
		if (mongo != null) {
			try {
				mongo.destroy(TestCommon.isDeleteTempFiles());
			} catch (IOException e) {
				System.out.println("Error deleting temporarary files at: " +
						TestCommon.getTempDir());
				e.printStackTrace();
			}
		}
	}
	
	@Before
	public void clearDB() throws Exception {
		TestCommon.destroyDB(db);
	}
}
