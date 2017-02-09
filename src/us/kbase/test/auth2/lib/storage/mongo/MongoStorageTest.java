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
		
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect login allowed", res.getCfg().isLoginAllowed(), is(true));
		assertThat("incorrect token lifetimes", res.getCfg().getTokenLifetimeMS(),
				is(ImmutableMap.of(TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L)));
		assertThat("incorrect provider config count", res.getCfg().getProviders().size(), is(2));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isEnabled(), is(false));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isForceLinkChoice(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isForceLinkChoice(), is(false));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	@Test
	public void updateConfigWithoutOverwrite() throws Exception {
		final AuthConfigSet<TestConfig> cfgSet = new AuthConfigSet<>(
				// should really consider making a builder for this
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
		
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect login allowed", res.getCfg().isLoginAllowed(), is(true));
		assertThat("incorrect token lifetimes", res.getCfg().getTokenLifetimeMS(),
				is(ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L)));
		assertThat("incorrect provider config count", res.getCfg().getProviders().size(), is(3));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isEnabled(), is(false));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isForceLinkChoice(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isForceLinkChoice(), is(false));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov3").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov3").isForceLinkChoice(), is(true));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	@Test
	public void updateConfigWithOverwrite() throws Exception {
		//also tests that a null value causes no update
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
		
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect login allowed", res.getCfg().isLoginAllowed(), is(false));
		assertThat("incorrect token lifetimes", res.getCfg().getTokenLifetimeMS(),
				is(ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 600000L,
						TokenLifetimeType.SERV, 800000L)));
		assertThat("incorrect provider config count", res.getCfg().getProviders().size(), is(3));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isForceLinkChoice(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isForceLinkChoice(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov3").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov3").isForceLinkChoice(), is(true));
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
		
		final AuthConfigSet<TestConfig> res = storage.getConfig(new TestConfigMapper());
		assertThat("incorrect login allowed", res.getCfg().isLoginAllowed(), is(true));
		assertThat("incorrect token lifetimes", res.getCfg().getTokenLifetimeMS(),
				is(ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L)));
		assertThat("incorrect provider config count", res.getCfg().getProviders().size(), is(3));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov1").isForceLinkChoice(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov2").isForceLinkChoice(), is(false));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov3").isEnabled(), is(true));
		assertThat("incorrect provider config",
				res.getCfg().getProviderConfig("prov3").isForceLinkChoice(), is(true));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
}
