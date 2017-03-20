package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Map;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.config.TestExternalConfig;
import us.kbase.test.auth2.lib.config.TestExternalConfig.TestExternalConfigMapper;

public class MongoStorageConfigTest extends MongoStorageTester {
	
	@Test
	public void getEmptyConfig() throws Exception {
		final AuthConfigSet<TestExternalConfig> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(new AuthConfig(null, null, null)));
		assertThat("incorrect external config", res.getExtcfg().aThing, is((String) null));
	}
	
	@Test
	public void updateConfigAndGet() throws Exception {
		final AuthConfigSet<TestExternalConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true, false),
						"prov2", new ProviderConfig(true, false, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L));
		final AuthConfigSet<TestExternalConfig> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	@Test
	public void updateConfigWithoutOverwrite() throws Exception {
		final AuthConfigSet<TestExternalConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(false,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true, true),
								"prov2", new ProviderConfig(true, true, true),
								"prov3", new ProviderConfig(true, true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.LOGIN, 600000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestExternalConfig("foo1"));
		storage.updateConfig(cfgSet2, false);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true, false),
						"prov2", new ProviderConfig(true, false, true),
						"prov3", new ProviderConfig(true, true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestExternalConfig> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	@Test
	public void updateConfigWithOverwrite() throws Exception {
		final AuthConfigSet<TestExternalConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(false,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true, true),
								"prov2", new ProviderConfig(true, true, true),
								"prov3", new ProviderConfig(true, true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.LOGIN, 600000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestExternalConfig("foo1"));
		storage.updateConfig(cfgSet2, true);
		
		final AuthConfig expected = new AuthConfig(false,
				ImmutableMap.of(
						"prov1", new ProviderConfig(true, true, true),
						"prov2", new ProviderConfig(true, true, true),
						"prov3", new ProviderConfig(true, true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 600000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestExternalConfig> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo1"));
	}
	
	@Test
	public void updateConfigWithOverwriteAndNullValues() throws Exception {
		// tests that a null value causes no update
		// if you believe Google (and I probably should) I should use an Optional instead of nulls
		final AuthConfigSet<TestExternalConfig> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig("foo"));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(null,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true, true),
								"prov2", new ProviderConfig(null, null, null),
								"prov3", new ProviderConfig(true, true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestExternalConfig(null));
		storage.updateConfig(cfgSet2, true);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(true, true, true),
						"prov2", new ProviderConfig(true, false, true),
						"prov3", new ProviderConfig(true, true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestExternalConfig> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is("foo"));
	}
	
	private class BadMapper implements ExternalConfigMapper<TestExternalConfig> {

		@Override
		public TestExternalConfig fromMap(final Map<String, String> config)
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
	
	@Test
	public void getConfigFail() throws Exception {
		try {
			storage.getConfig(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("mapper"));
		}
	}
	
	@Test
	public void updateConfigFail() throws Exception {
		try {
			storage.updateConfig(null, true);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("cfgSet"));
		}
	}
}
