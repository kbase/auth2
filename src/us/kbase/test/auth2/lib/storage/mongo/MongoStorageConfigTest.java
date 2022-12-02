package us.kbase.test.auth2.lib.storage.mongo;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Map;
import java.util.Optional;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.AuthConfigUpdate.ProviderUpdate;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.config.ExternalConfigMapper;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.config.TestExternalConfig;
import us.kbase.test.auth2.lib.config.TestExternalConfig.TestExternalConfigMapper;

public class MongoStorageConfigTest extends MongoStorageTester {
	
	private static final ConfigItem<String, State> STATE_FOO = ConfigItem.state("foo");
	
	@Test
	public void getEmptyConfig() throws Exception {
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(new AuthConfig(false, null, null)));
		assertThat("incorrect external config", res.getExtcfg().aThing,
				is((ConfigItem<String, State>) null));
	}
	
	@Test
	public void updateConfigAndGetWithAllTokenLifeTimes() throws Exception {
		final AuthConfigUpdate<ExternalConfig> cfgUp = AuthConfigUpdate.getBuilder()
				.withTokenLifeTime(TokenLifetimeType.EXT_CACHE, 100000L)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 200000L)
				.withTokenLifeTime(TokenLifetimeType.AGENT, 300000L)
				.withTokenLifeTime(TokenLifetimeType.DEV, 400000L)
				.withTokenLifeTime(TokenLifetimeType.SERV, 500000L)
				.build();
		storage.updateConfig(cfgUp, false);
		
		final AuthConfig expected = new AuthConfig(false, null,
				ImmutableMap.of(
						TokenLifetimeType.EXT_CACHE, 100000L,
						TokenLifetimeType.LOGIN, 200000L,
						TokenLifetimeType.AGENT, 300000L,
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.SERV, 500000L));
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing,
				is((ConfigItem<String, State>) null));
	}
	
	@Test
	public void updateConfigAndGet() throws Exception {
		final AuthConfigUpdate<ExternalConfig> cfgUp = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(true)
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withProviderUpdate("prov2", new ProviderUpdate(true, false, true))
				.withTokenLifeTime(TokenLifetimeType.DEV, 200000L)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 300000L)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build();
		storage.updateConfig(cfgUp, false);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true, false),
						"prov2", new ProviderConfig(true, false, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L));
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	@Test
	public void updateConfigWithoutOverwrite() throws Exception {
		final AuthConfigUpdate<ExternalConfig> cfgUp = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(true)
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withProviderUpdate("prov2", new ProviderUpdate(true, false, true))
				.withTokenLifeTime(TokenLifetimeType.DEV, 200000L)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 300000L)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build();
		storage.updateConfig(cfgUp, false);
		
		final AuthConfigUpdate<ExternalConfig> cfgUp2 = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov1", new ProviderUpdate(true, true, true))
				.withProviderUpdate("prov2", new ProviderUpdate(true, true, true))
				.withProviderUpdate("prov3", new ProviderUpdate(true, true, true))
				.withTokenLifeTime(TokenLifetimeType.DEV, 400000L)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 600000L)
				.withTokenLifeTime(TokenLifetimeType.SERV, 800000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo1")))
				.build();
		storage.updateConfig(cfgUp2, false);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true, false),
						"prov2", new ProviderConfig(true, false, true),
						"prov3", new ProviderConfig(true, true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 200000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	@Test
	public void updateConfigWithOverwrite() throws Exception {
		final AuthConfigUpdate<ExternalConfig> cfgUp = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(true)
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withProviderUpdate("prov2", new ProviderUpdate(true, false, true))
				.withTokenLifeTime(TokenLifetimeType.DEV, 200000L)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 300000L)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build();
		storage.updateConfig(cfgUp, false);
		

		final AuthConfigUpdate<ExternalConfig> cfgUp2 = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withProviderUpdate("prov1", new ProviderUpdate(true, true, true))
				.withProviderUpdate("prov2", new ProviderUpdate(true, true, true))
				.withProviderUpdate("prov3", new ProviderUpdate(true, true, true))
				.withTokenLifeTime(TokenLifetimeType.DEV, 400000L)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 600000L)
				.withTokenLifeTime(TokenLifetimeType.SERV, 800000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo1")))
				.build();
		storage.updateConfig(cfgUp2, true);
		
		final AuthConfig expected = new AuthConfig(false,
				ImmutableMap.of(
						"prov1", new ProviderConfig(true, true, true),
						"prov2", new ProviderConfig(true, true, true),
						"prov3", new ProviderConfig(true, true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 600000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing,
				is(ConfigItem.state("foo1")));
	}
	
	@Test
	public void updateConfigRemoveExternal() throws Exception {
		storage.updateConfig(AuthConfigUpdate.getBuilder()
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.withLoginAllowed(true).build(), false);
		
		storage.updateConfig(AuthConfigUpdate.getBuilder()
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.remove()))
				.build(), true);
		
		final AuthConfig expected = new AuthConfig(true, null, null);
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing,
				is((ConfigItem<String, State>) null));
	}
	
	@Test
	public void updateConfigRemoveExternalWithoutOverwrite() throws Exception {
		storage.updateConfig(AuthConfigUpdate.getBuilder()
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.withLoginAllowed(true).build(), false);
		
		storage.updateConfig(AuthConfigUpdate.getBuilder()
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.remove()))
				.build(), false);
		
		final AuthConfig expected = new AuthConfig(true, null, null);
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	@Test
	public void updateConfigWithOverwriteAndOptionalValues() throws Exception {
		final AuthConfigUpdate<ExternalConfig> cfgUp = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(true)
				.withProviderUpdate("prov1", new ProviderUpdate(false, true, false))
				.withProviderUpdate("prov2", new ProviderUpdate(true, false, true))
				.withTokenLifeTime(TokenLifetimeType.DEV, 200000L)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 300000L)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.set("foo")))
				.build();
		storage.updateConfig(cfgUp, false);
		
		final Optional<Boolean> ab = Optional.empty();
		final AuthConfigUpdate<ExternalConfig> cfgUp2 = AuthConfigUpdate.getBuilder()
				// leave out login allowed = absent value supplied
				.withProviderUpdate("prov2", new ProviderUpdate(ab, ab, ab))
				.withProviderUpdate("prov3", new ProviderUpdate(true, true, true))
				.withTokenLifeTime(TokenLifetimeType.DEV, 400000L)
				.withTokenLifeTime(TokenLifetimeType.SERV, 800000)
				.withExternalConfig(new TestExternalConfig<>(ConfigItem.noAction()))
				.build();
		storage.updateConfig(cfgUp2, true);
		
		final AuthConfig expected = new AuthConfig(true,
				ImmutableMap.of(
						"prov1", new ProviderConfig(false, true, false),
						"prov2", new ProviderConfig(true, false, true),
						"prov3", new ProviderConfig(true, true, true)),
				ImmutableMap.of(
						TokenLifetimeType.DEV, 400000L,
						TokenLifetimeType.LOGIN, 300000L,
						TokenLifetimeType.SERV, 800000L));
		final AuthConfigSet<TestExternalConfig<State>> res = storage.getConfig(
				new TestExternalConfigMapper());
		assertThat("incorrect config", res.getCfg(), is(expected));
		assertThat("incorrect external config", res.getExtcfg().aThing, is(STATE_FOO));
	}
	
	private class BadMapper implements ExternalConfigMapper<TestExternalConfig<State>> {

		@Override
		public TestExternalConfig<State> fromMap(
				final Map<String, ConfigItem<String, State>> config)
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
