package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import us.kbase.common.test.controllers.mongo.MongoController;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTest {

	private static MongoController mongo;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		mongo = new MongoController(TestCommon.getMongoExe().toString(),
				TestCommon.getTempDir(),
				TestCommon.useWiredTigerEngine());
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		if (mongo != null) {
			mongo.destroy(TestCommon.isDeleteTempFiles());
		}
	}
	
	@Before
	public void clearDB() throws Exception {
//		TestCommon.destroyDB(jdb.getDatabase());
	}
	
	@Test
	public void foo() {
		
	}
}
