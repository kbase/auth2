package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.collect.ImmutableMap;
import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.ExternalConfigMapper;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.common.test.controllers.mongo.MongoController;
import us.kbase.test.auth2.TestCommon;

public class MongoStorageTest {

	private static MongoController mongo;
	private static MongoClient mc;
	private static MongoDatabase db;
	private static MongoStorage storage;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		mongo = new MongoController(TestCommon.getMongoExe().toString(),
				TestCommon.getTempDir(),
				TestCommon.useWiredTigerEngine());
		mc = new MongoClient("localhost:" + mongo.getServerPort());
		db = mc.getDatabase("test_mongostorage");
		storage = new MongoStorage(db);
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		mc.close();
		if (mongo != null) {
			mongo.destroy(TestCommon.isDeleteTempFiles());
		}
	}
	
	@Before
	public void clearDB() throws Exception {
		TestCommon.destroyDB(db);
	}
	
	private class TestConfig implements ExternalConfig {
		
		private final String aThing;
		
		public TestConfig(final String thing) {
			aThing = thing;
		}

		@Override
		public Map<String, String> toMap() {
			final Map<String, String> ret = new HashMap<>();
			ret.put("thing", aThing);
			return ret;
		}
	}
	
	private class TestConfigMapper implements ExternalConfigMapper<TestConfig> {

		@Override
		public TestConfig fromMap(final Map<String, String> config)
				throws ExternalConfigMappingException {
			return new TestConfig(config.get("thing"));
		}
		
	}
	
	@Test
	public void getEmptyConfig() throws Exception {
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(new AuthConfig(null, null, null)));
		assertThat("incorrect external config", res.getExtcfg().aThing, is((String) null));
	}
	
	@Test
	public void updateConfigAndGet() throws Exception {
		final AuthConfigSet<TestConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true),
								"prov2", new ProviderConfig(true, false)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true),
						"prov2", new ProviderConfig(true, false)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L));
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	@Test
	public void updateConfigWithoutOverwrite() throws Exception {
		final AuthConfigSet<TestConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true),
								"prov2", new ProviderConfig(true, false)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestConfig> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(false,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true),
								"prov2", new ProviderConfig(true, true),
								"prov3", new ProviderConfig(true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.LOGIN, 600000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestConfig("foo1"));
		storage.updateConfig(cfgSet2, false);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true),
						"prov2", new ProviderConfig(true, false),
						"prov3", new ProviderConfig(true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	@Test
	public void updateConfigWithOverwrite() throws Exception {
		final AuthConfigSet<TestConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true),
								"prov2", new ProviderConfig(true, false)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestConfig> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(false,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true),
								"prov2", new ProviderConfig(true, true),
								"prov3", new ProviderConfig(true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.LOGIN, 600000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestConfig("foo1"));
		storage.updateConfig(cfgSet2, true);
		
		final AuthConfig expected = new AuthConfig(false,
				ImmutableMap.of(
						"prov1", new ProviderConfig(true, true),
						"prov2", new ProviderConfig(true, true),
						"prov3", new ProviderConfig(true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 600000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo1"));
	}
	
	@Test
	public void updateConfigWithOverwriteAndNullValues() throws Exception {
		// tests that a null value causes no update
		// if you believe Google (and I probably should) I should use an Optional instead of nulls
		final AuthConfigSet<TestConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true),
								"prov2", new ProviderConfig(true, false)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestConfig> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(null,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true),
								"prov2", new ProviderConfig(null, null),
								"prov3", new ProviderConfig(true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestConfig(null));
		storage.updateConfig(cfgSet2, true);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(true, true),
						"prov2", new ProviderConfig(true, false),
						"prov3", new ProviderConfig(true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	private class BadMapper implements ExternalConfigMapper<TestConfig> {

		@Override
		public TestConfig fromMap(final Map<String, String> config)
				throws ExternalConfigMappingException {
			throw new ExternalConfigMappingException("borkborkbork");
		}
	}
	
	@Test
	public void externalConfigMappingException() throws Exception {
		try {
			storage.getConfig(new BadMapper());
			fail("expected exception");
		} catch (ExternalConfigMappingException e) {
			assertThat("correct exception message", e.getMessage(), is("borkborkbork"));
		}
	}
}
