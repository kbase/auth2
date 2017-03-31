package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Map;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.ConfigState;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.config.TestExternalConfig;
import us.kbase.test.auth2.lib.config.TestExternalConfig.TestExternalConfigMapper;

public class MongoStorageConfigTest extends MongoStorageTester {
	
	private static final ConfigItem<String, ConfigState> STATE_FOO = ConfigItem.state("foo");
	
	@Test
	public void getEmptyConfig() throws Exception {
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(new AuthConfig(null, null, null)));
		assertThat("incorrect external config", res.getExtcfg().aThing,
				is((ConfigItem<String, ConfigState>) null));
	}
	
	@Test
	public void updateConfigAndGetWithAllTokenLifeTimes() throws Exception {
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true, null,
						ImmutableMap.of(
								TokenLifetimeType.EXT_CACHE, 100000L,
								TokenLifetimeType.LOGIN, 200000L,
								TokenLifetimeType.AGENT, 300000L,
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.SERV, 500000L)),
				new TestExternalConfig<>(ConfigItem.set("foo")));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfig expected = new AuthConfig(true, null,
				ImmutableMap.of(
						TokenLifetimeType.EXT_CACHE, 100000L,
						TokenLifetimeType.LOGIN, 200000L,
						TokenLifetimeType.AGENT, 300000L,
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.SERV, 500000L));
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	@Test
	public void updateConfigAndGet() throws Exception {
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig<>(ConfigItem.set("foo")));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true, false),
						"prov2", new ProviderConfig(true, false, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L));
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	@Test
	public void updateConfigWithoutOverwrite() throws Exception {
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig<>(ConfigItem.set("foo")));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(false,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true, true),
								"prov2", new ProviderConfig(true, true, true),
								"prov3", new ProviderConfig(true, true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.LOGIN, 600000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestExternalConfig<>(ConfigItem.set("foo1")));
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
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	@Test
	public void updateConfigWithOverwrite() throws Exception {
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig<>(ConfigItem.set("foo")));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(false,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true, true),
								"prov2", new ProviderConfig(true, true, true),
								"prov3", new ProviderConfig(true, true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.LOGIN, 600000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestExternalConfig<>(ConfigItem.set("foo1")));
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
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing,
				is(ConfigItem.state("foo1")));
	}
	
	@Test
	public void updateConfigRemoveExternal() throws Exception {
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true, null, null),
				new TestExternalConfig<>(ConfigItem.set("foo")));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(true, null, null),
				new TestExternalConfig<>(ConfigItem.remove()));
		storage.updateConfig(cfgSet2, true);
		
		final AuthConfig expected = new AuthConfig(true, null, null);
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing,
				is((ConfigItem<String, ConfigState>) null));
	}
	
	@Test
	public void updateConfigRemoveExternalWithoutOverwrite() throws Exception {
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true, null, null),
				new TestExternalConfig<>(ConfigItem.set("foo")));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(true, null, null),
				new TestExternalConfig<>(ConfigItem.remove()));
		storage.updateConfig(cfgSet2, false);
		
		final AuthConfig expected = new AuthConfig(true, null, null);
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	@Test
	public void updateConfigWithOverwriteAndNullValues() throws Exception {
		// tests that a null value causes no update
		// if you believe Google (and I probably should) I should use an Optional instead of nulls
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet = new AuthConfigSet<>(
				new AuthConfig(true,
						ImmutableMap.of(
								"prov1", new ProviderConfig(false, true, false),
								"prov2", new ProviderConfig(true, false, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 200000L,
								TokenLifetimeType.LOGIN, 300000L)),
				new TestExternalConfig<>(ConfigItem.set("foo")));
		storage.updateConfig(cfgSet, false);
		
		final AuthConfigSet<TestExternalConfig<Action>> cfgSet2 = new AuthConfigSet<>(
				new AuthConfig(null,
						ImmutableMap.of(
								"prov1", new ProviderConfig(true, true, true),
								"prov2", new ProviderConfig(null, null, null),
								"prov3", new ProviderConfig(true, true, true)),
						ImmutableMap.of(
								TokenLifetimeType.DEV, 400000L,
								TokenLifetimeType.SERV, 800000L)),
				new TestExternalConfig<>(ConfigItem.noAction()));
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
		final AuthConfigSet<TestExternalConfig<ConfigState>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	private class BadMapper implements ExternalConfigMapper<TestExternalConfig<ConfigState>> {

		@Override
		public TestExternalConfig<ConfigState> fromMap(
				final Map<String, ConfigItem<String, ConfigState>> config)
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
