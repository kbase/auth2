package us.kbase.test.auth2.lib.storage.mongo;

import java.time.Clock;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;

import com.github.zafarkhaja.semver.Version;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.common.test.controllers.mongo.MongoController;
import us.kbase.test.auth2.MongoStorageTestManager;

public class MongoStorageTester {
	
	static MongoStorageTestManager manager;

	//keeping these so the tests don't have to be refactored. Should really just use the manager
	static MongoController mongo;
	static MongoClient mc;
	static MongoDatabase db;
	static MongoStorage storage;
	static Clock mockClock;
	static Version mongoDBVer;
	static int indexVer;
	static boolean includeSystemIndexes;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		manager = new MongoStorageTestManager("test_mongostorage");
		mongo = manager.mongo;
		mc = manager.mc;
		db = manager.db;
		storage = manager.storage;
		mockClock = manager.mockClock;
		mongoDBVer = manager.mongoDBVer;
		indexVer = manager.indexVer;
		includeSystemIndexes = mongoDBVer.lessThan(Version.forIntegers(3, 2)) &&
				!manager.wiredTiger;
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		manager.destroy();
	}
	
	@Before
	public void clearDB() throws Exception {
		manager.reset();
		storage = manager.storage;
		mockClock = manager.mockClock;
	}
}
