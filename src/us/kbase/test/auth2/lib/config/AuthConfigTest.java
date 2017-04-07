package us.kbase.test.auth2.lib.config;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

import org.junit.Test;

import com.google.common.base.Optional;
import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.AuthConfigSetWithUpdateTime;
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.AuthConfigUpdate.ProviderUpdate;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.test.auth2.TestCommon;

public class AuthConfigTest {

	@Test
	public void configItemEquals() throws Exception {
		EqualsVerifier.forClass(ConfigItem.class).usingGetClass().verify();
	}
	
	@Test
	public void configItemNoAction() throws Exception {
		final ConfigItem<String, Action> ci = ConfigItem.noAction();
		
		assertThat("incorrect isstate", ci.getAction().isState(), is(false));
		assertThat("incorrect isnoaction", ci.getAction().isNoAction(), is(true));
		assertThat("incorrect isremove", ci.getAction().isRemove(), is(false));
		assertThat("incorrect isset", ci.getAction().isSet(), is(false));
		assertThat("incorrect hasItem", ci.hasItem(), is(false));
		assertThat("incorrect toString", ci.toString(),
				is("ConfigItem [item=null, action=NoAction]"));
		failGetItem(ci);
	}
	
	@Test
	public void configItemRemove() throws Exception {
		final ConfigItem<String, Action> ci = ConfigItem.remove();
		
		assertThat("incorrect isstate", ci.getAction().isState(), is(false));
		assertThat("incorrect isnoaction", ci.getAction().isNoAction(), is(false));
		assertThat("incorrect isremove", ci.getAction().isRemove(), is(true));
		assertThat("incorrect isset", ci.getAction().isSet(), is(false));
		assertThat("incorrect hasItem", ci.hasItem(), is(false));
		assertThat("incorrect toString", ci.toString(),
				is("ConfigItem [item=null, action=RemoveAction]"));
		failGetItem(ci);
	}
	
	@Test
	public void configItemSet() throws Exception {
		final ConfigItem<String, Action> ci = ConfigItem.set("foo");
		
		assertThat("incorrect isstate", ci.getAction().isState(), is(false));
		assertThat("incorrect isnoaction", ci.getAction().isNoAction(), is(false));
		assertThat("incorrect isremove", ci.getAction().isRemove(), is(false));
		assertThat("incorrect isset", ci.getAction().isSet(), is(true));
		assertThat("incorrect hasItem", ci.hasItem(), is(true));
		assertThat("incorrect getItem", ci.getItem(), is("foo"));
		assertThat("incorrect toString", ci.toString(),
				is("ConfigItem [item=foo, action=SetAction]"));
		
		try {
			ConfigItem.set(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("item"));
		}
	}
	
	@Test
	public void configItemState() throws Exception {
		final ConfigItem<String, State> ci = ConfigItem.state("foo");
		
		assertThat("incorrect isstate", ci.getAction().isState(), is(true));
		assertThat("incorrect isnoaction", ci.getAction().isNoAction(), is(false));
		assertThat("incorrect isremove", ci.getAction().isRemove(), is(false));
		assertThat("incorrect isset", ci.getAction().isSet(), is(false));
		assertThat("incorrect hasItem", ci.hasItem(), is(true));
		assertThat("incorrect getItem", ci.getItem(), is("foo"));
		assertThat("incorrect toString", ci.toString(), is("ConfigItem [item=foo, action=State]"));
		
		try {
			ConfigItem.state(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("item"));
		}
	}
	
	@Test
	public void configItemEmptyState() throws Exception {
		final ConfigItem<String, State> ci = ConfigItem.emptyState();
		
		assertThat("incorrect isstate", ci.getAction().isState(), is(true));
		assertThat("incorrect isnoaction", ci.getAction().isNoAction(), is(false));
		assertThat("incorrect isremove", ci.getAction().isRemove(), is(false));
		assertThat("incorrect isset", ci.getAction().isSet(), is(false));
		assertThat("incorrect hasItem", ci.hasItem(), is(false));
		assertThat("incorrect toString", ci.toString(),
				is("ConfigItem [item=null, action=State]"));
		failGetItem(ci);
	}
	
	private void failGetItem(final ConfigItem<String, ?> ci) {
		try {
			ci.getItem();
			fail("expected exception");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, new IllegalStateException(
					"getItem() cannot be called on an absent item"));
		}
	}

	@Test
	public void defaults() throws Exception {
		assertThat("incorrect login default", AuthConfig.DEFAULT_LOGIN_ALLOWED, is(false));
		final Map<TokenLifetimeType, Long> defaultLifeTimes = new HashMap<>();
		defaultLifeTimes.put(TokenLifetimeType.AGENT, 7 * 24 * 60 * 60 * 1000L);
		defaultLifeTimes.put(TokenLifetimeType.LOGIN, 14 * 24 * 60 * 60 * 1000L);
		defaultLifeTimes.put(TokenLifetimeType.DEV, 90 * 24 * 60 * 60 * 1000L);
		defaultLifeTimes.put(TokenLifetimeType.SERV, 100_000_000L * 24 * 60 * 60 * 1000L);
		defaultLifeTimes.put(TokenLifetimeType.EXT_CACHE, 5 * 60 * 1000L);
		assertThat("incorrect token lifetimes", AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS,
				is(defaultLifeTimes));
	}
	
	@Test
	public void providerConfig() throws Exception {
		final ProviderConfig pc = new ProviderConfig(false, true, false);
		assertThat("incorrect enabled", pc.isEnabled(), is(false));
		assertThat("incorrect force login", pc.isForceLoginChoice(), is(true));
		assertThat("incorrect force link", pc.isForceLinkChoice(), is(false));
		assertThat("incorrect to string", pc.toString(), is(
				"ProviderConfig [enabled=false, forceLoginChoice=true, forceLinkChoice=false]"));
	}
	
	@Test
	public void providerEquals() {
		EqualsVerifier.forClass(ProviderConfig.class).usingGetClass().verify();
	}
	
	@Test
	public void authConfigEquals() {
		EqualsVerifier.forClass(AuthConfig.class).usingGetClass().verify();
	}
	
	@Test
	public void constructAndGettersSuccess() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put("pc1", new ProviderConfig(true, true, false));
		pc.put("pc2", new ProviderConfig(false, false, true));
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		lts.put(TokenLifetimeType.DEV, 500000L);
		lts.put(TokenLifetimeType.LOGIN, 70000000L);
		
		final AuthConfig ac = new AuthConfig(false, pc, lts);
		final Map<TokenLifetimeType, Long> ltscopy = new HashMap<>(lts);
		final Map<String, ProviderConfig> pccopy = new HashMap<>(pc);
		// modify input maps to ensure does not modify config instance
		pc.remove("pc1");
		lts.remove(TokenLifetimeType.DEV);
		lts.put(TokenLifetimeType.EXT_CACHE, 6000000L);
		
		assertThat("incorrect login allowed", ac.isLoginAllowed(), is(false));
		assertThat("incorrect providers", ac.getProviders(), is(pccopy));
		assertThat("incorrect lifetimes", ac.getTokenLifetimeMS(), is(ltscopy));
		assertThat("incorrect provider enabled", ac.getProviderConfig("pc1").isEnabled(),
				is(true));
		assertThat("incorrect provider force login",
				ac.getProviderConfig("pc1").isForceLoginChoice(), is(true));
		assertThat("incorrect provider force link",
				ac.getProviderConfig("pc1").isForceLinkChoice(), is(false));
		assertThat("incorrect provider enabled", ac.getProviderConfig("pc2").isEnabled(),
				is(false));
		assertThat("incorrect provider force login",
				ac.getProviderConfig("pc2").isForceLoginChoice(), is(false));
		assertThat("incorrect provider force link",
				ac.getProviderConfig("pc2").isForceLinkChoice(), is(true));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.EXT_CACHE),
				is(5 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.AGENT),
				is(7 * 24 * 60 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.LOGIN),
				is(70000000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.DEV),
				is(500000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.SERV),
				is(8640000000000000L));
		assertThat("incorrect to string", ac.toString(), is(
				"AuthConfig [loginAllowed=false, providers={" +
				"pc1=ProviderConfig [enabled=true, forceLoginChoice=true, " +
						"forceLinkChoice=false], " +
				"pc2=ProviderConfig [enabled=false, forceLoginChoice=false, " +
				"forceLinkChoice=true]}, tokenLifetimeMS={LOGIN=70000000, DEV=500000}]"));
	}
	
	@Test
	public void constructAndGettersWithNullsSuccess() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		
		final AuthConfig ac = new AuthConfig(true, null, null);
		final Map<TokenLifetimeType, Long> ltscopy = new HashMap<>(lts);
		final Map<String, ProviderConfig> pccopy = new HashMap<>(pc);
		// modify input maps to ensure does not modify config instance
		pc.put("foo", new ProviderConfig(false, false, false));
		lts.put(TokenLifetimeType.EXT_CACHE, 6000000L);
		
		assertThat("incorrect login allowed", ac.isLoginAllowed(), is(true));
		assertThat("incorrect providers", ac.getProviders(), is(pccopy));
		assertThat("incorrect lifetimes", ac.getTokenLifetimeMS(), is(ltscopy));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.EXT_CACHE),
				is(5 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.AGENT),
				is(7 * 24 * 60 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.LOGIN),
				is(14 * 24 * 60 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.DEV),
				is(90 * 24 * 60 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.SERV),
				is(8640000000000000L));
		assertThat("incorrect to string", ac.toString(), is(
				"AuthConfig [loginAllowed=true, providers={}, tokenLifetimeMS={}]"));
	}
	
	@Test
	public void authConfigFilterProviders() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put("pc1", new ProviderConfig(true, true, false));
		pc.put("pc2", new ProviderConfig(false, false, true));
		
		final AuthConfig ac = new AuthConfig(false, pc, null);
		
		final AuthConfig filtered = ac.filterProviders(new HashSet<>(Arrays.asList("pc2", "pc3")));
		assertThat("incorrect login allowed", filtered.isLoginAllowed(), is(false));
		assertThat("incorrect providers", filtered.getProviders(), is(ImmutableMap.of(
				"pc2", new ProviderConfig(false, false, true))));
		assertThat("incorrect lifetimes", filtered.getTokenLifetimeMS(),
				is(Collections.emptyMap()));
	}
	
	@Test
	public void authConfigFilterProvidersEmpty() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put("pc1", new ProviderConfig(true, true, false));
		pc.put("pc2", new ProviderConfig(false, false, true));
		
		final AuthConfig ac = new AuthConfig(false, pc, null);
		
		final AuthConfig filtered = ac.filterProviders(Collections.emptySet());
		assertThat("incorrect login allowed", filtered.isLoginAllowed(), is(false));
		assertThat("incorrect providers", filtered.getProviders(), is(Collections.emptyMap()));
		assertThat("incorrect lifetimes", filtered.getTokenLifetimeMS(),
				is(Collections.emptyMap()));
	}
	
	@Test
	public void authConfigFilterFailNull() throws Exception {
		try {
			new AuthConfig(false, null, null).filterProviders(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("identityProviders"));
		}
	}
	
	@Test
	public void getProviderFail() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put("pc1", new ProviderConfig(true, true, false));
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		
		final AuthConfig ac = new AuthConfig(true, pc, lts);
		failGetProvider(ac, null, null);
		failGetProvider(ac, "", "");
		failGetProvider(ac, "pc2", "pc2");
	}

	private void failGetProvider(final AuthConfig ac, final String provider, final String err) {
		try {
			ac.getProviderConfig(provider);
			fail("got bad provider");
		} catch (NoSuchIdentityProviderException e) {
			TestCommon.assertExceptionCorrect(e, new NoSuchIdentityProviderException(err));
		}
	}
	
	@Test
	public void constructFailOnProvider() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put(null, new ProviderConfig(false, false, false));
		failConstructAuthConfig(pc, null, new IllegalArgumentException(
				"provider names cannot be null or empty"));
		
		pc.clear();
		pc.put("  \t  ", new ProviderConfig(true, true, true));
		failConstructAuthConfig(pc, null, new IllegalArgumentException(
				"provider names cannot be null or empty"));
		
		pc.clear();
		pc.put("pc", null);
		failConstructAuthConfig(pc, null, new NullPointerException(
				"provider config for provider pc is null"));
	}
	
	@Test
	public void constructFailOnLifetimes() throws Exception {
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		lts.put(null, 3000000L);
		failConstructAuthConfig(null, lts, new NullPointerException(
				"null key in token life time map"));
		
		lts.clear();
		lts.put(TokenLifetimeType.DEV, null);
		failConstructAuthConfig(null, lts, new NullPointerException(
				"lifetime for key DEV is null"));
		
		lts.clear();
		lts.put(TokenLifetimeType.SERV, 59999L);
		failConstructAuthConfig(null, lts, new IllegalArgumentException(
				"lifetime for key SERV must be at least 60000 ms"));
	}

	private void failConstructAuthConfig(
			final Map<String, ProviderConfig> providers,
			final Map<TokenLifetimeType, Long> lifetimes,
			final Exception exception) {
		try {
			new AuthConfig(true, providers, lifetimes);
			fail("created bad config");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	static class TestExtCfg implements ExternalConfig {
		
		private int i = 1;

		@Override
		public Map<String, ConfigItem<String, Action>> toMap() {
			return ImmutableMap.of("foo", ConfigItem.set("bar"));
		}
		
		@Override
		public String toString() {
			return "This is a very poor toString() implementation. Sad!";
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + i;
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}
			TestExtCfg other = (TestExtCfg) obj;
			if (i != other.i) {
				return false;
			}
			return true;
		}
	}

	@Test
	public void updateConfigProviderEquals() {
		EqualsVerifier.forClass(ProviderUpdate.class).usingGetClass().verify();
	}
	
	@Test
	public void updateConfigProviderDefault() throws Exception {
		final ProviderUpdate pu = AuthConfigUpdate.DEFAULT_PROVIDER_UPDATE;
		assertThat("incorrect enabled", pu.getEnabled(), is(Optional.of(false)));
		assertThat("incorrect force login", pu.getForceLoginChoice(), is(Optional.of(false)));
		assertThat("incorrect force link", pu.getForceLinkChoice(), is(Optional.of(false)));
	}
	
	@Test
	public void updateConfigProviderConstructBoolean() throws Exception {
		final ProviderUpdate pu = new ProviderUpdate(false, true, false);
		assertThat("incorrect enabled", pu.getEnabled(), is(Optional.of(false)));
		assertThat("incorrect force login", pu.getForceLoginChoice(), is(Optional.of(true)));
		assertThat("incorrect force link", pu.getForceLinkChoice(), is(Optional.of(false)));
	}
	
	@Test
	public void updateConfigProviderConstructOptional() throws Exception {
		final ProviderUpdate pu = new ProviderUpdate(Optional.of(false),
				Optional.of(true), Optional.of(false));
		assertThat("incorrect enabled", pu.getEnabled(), is(Optional.of(false)));
		assertThat("incorrect force login", pu.getForceLoginChoice(), is(Optional.of(true)));
		assertThat("incorrect force link", pu.getForceLinkChoice(), is(Optional.of(false)));
	}
	
	@Test
	public void updatgeConfigProviderConstructFailNulls() throws Exception {
		final Optional<Boolean> o = Optional.of(false);
		failUpdateConfigProviderConstruct(null, o, o, new NullPointerException("enabled"));
		failUpdateConfigProviderConstruct(o, null, o,
				new NullPointerException("forceLoginChoice"));
		failUpdateConfigProviderConstruct(o, o, null, new NullPointerException("forceLinkChoice"));
	}
	
	private void failUpdateConfigProviderConstruct(
			final Optional<Boolean> enabled,
			final Optional<Boolean> forceLogin,
			final Optional<Boolean> forceLink,
			final Exception e) {
		try {
			new ProviderUpdate(enabled, forceLogin, forceLink);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void updateConfigEquals() {
		EqualsVerifier.forClass(AuthConfigUpdate.class).usingGetClass().verify();
	}
	
	@Test
	public void updateConfigMinimal() throws Exception {
		final AuthConfigUpdate<ExternalConfig> acu = AuthConfigUpdate.getBuilder().build();
		assertThat("incorrect login", acu.getLoginAllowed(), is(Optional.absent()));
		assertThat("incorrect ext cfg", acu.getExternalConfig(), is(Optional.absent()));
		assertThat("incorrect providers", acu.getProviders(), is(Collections.emptyMap()));
		assertThat("incorrect token lifetimes", acu.getTokenLifetimeMS(), is(Collections.emptyMap()));
	}
	
	@Test
	public void updateConfigMaximal() throws Exception {
		final AuthConfigUpdate<TestExtCfg> acu = AuthConfigUpdate.<TestExtCfg>getBuilder()
				.withLoginAllowed(true)
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 60000)
				.withProviderUpdate("prov", new ProviderUpdate(false, true, true))
				.withExternalConfig(new TestExtCfg())
				.build();
		
		assertThat("incorrect login", acu.getLoginAllowed(), is(Optional.of(true)));
		assertThat("incorrect ext cfg", acu.getExternalConfig(), is(Optional.of(new TestExtCfg())));
		assertThat("incorrect providers", acu.getProviders(), is(ImmutableMap.of(
				"prov", new ProviderUpdate(false, true, true))));
		assertThat("incorrect token lifetime", acu.getTokenLifetimeMS(), is(ImmutableMap.of(
				TokenLifetimeType.LOGIN, 60000L)));
	}
	
	@Test
	public void updateConfigWithDefaultTokenLifetimes() throws Exception {
		final AuthConfigUpdate<ExternalConfig> acu = AuthConfigUpdate.getBuilder()
				.withLoginAllowed(false)
				.withDefaultTokenLifeTimes()
				.withTokenLifeTime(TokenLifetimeType.LOGIN, 60000)
				.build();
		
		assertThat("incorrect login", acu.getLoginAllowed(), is(Optional.of(false)));
		assertThat("incorrect ext cfg", acu.getExternalConfig(), is(Optional.absent()));
		assertThat("incorrect providers", acu.getProviders(), is(Collections.emptyMap()));
		assertThat("incorrect token lifetime", acu.getTokenLifetimeMS(), is(ImmutableMap.of(
				TokenLifetimeType.LOGIN, 60000L,
				TokenLifetimeType.AGENT, 7 * 24 * 3600 * 1000L,
				TokenLifetimeType.DEV, 90 * 24 * 3600 * 1000L,
				TokenLifetimeType.SERV, 100_000_000L * 24 * 3600 * 1000L,
				TokenLifetimeType.EXT_CACHE, 5 * 60 * 1000L)));
	}
	
	@Test
	public void updateConfigFail() throws Exception {
		final TokenLifetimeType tlt = TokenLifetimeType.LOGIN;
		final long life = 60000;
		final String prov = "foo";
		final ProviderUpdate pu = new ProviderUpdate(false, false, false);
		final ExternalConfig ec = new TestExtCfg();
		
		failUpdateConfigBuild(null, life, prov, pu, ec, new NullPointerException("lifetimeType"));
		failUpdateConfigBuild(tlt, 59999, prov, pu, ec,
				new IllegalArgumentException("token lifetime must be at least 60000 ms"));
		failUpdateConfigBuild(tlt, life, null, pu, ec, new MissingParameterException("provider"));
		failUpdateConfigBuild(tlt, life, "    \t  ", pu, ec,
				new MissingParameterException("provider"));
		failUpdateConfigBuild(tlt, life, prov, null, ec, new NullPointerException("update"));
		failUpdateConfigBuild(tlt, life, prov, pu, null, new NullPointerException("config"));
	}
	
	private void failUpdateConfigBuild(
			final TokenLifetimeType tlt,
			final long lifetimeMS,
			final String provider,
			final ProviderUpdate update,
			final ExternalConfig ec,
			final Exception e) {
		try {
			AuthConfigUpdate.getBuilder().withExternalConfig(ec)
					.withProviderUpdate(provider, update)
					.withTokenLifeTime(tlt, lifetimeMS);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
		
	}
	
	@Test
	public void configSetConstructAndGetters() throws Exception {
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		lts.put(TokenLifetimeType.DEV, 350000L);
		final AuthConfig cfg = new AuthConfig(false, null, lts);
		final AuthConfigSet<TestExtCfg> ac = new AuthConfigSet<TestExtCfg>(cfg, new TestExtCfg());
		assertThat("incorrect config login", ac.getCfg().isLoginAllowed(), is(false));
		assertThat("incorrect config providers", ac.getCfg().getProviders(), is(new HashMap<>()));
		assertThat("incorrect config token lifetimes", ac.getCfg().getTokenLifetimeMS(),
				is(lts));
		assertThat("incorrect ext config", ac.getExtcfg().toMap(),
				is(ImmutableMap.of("foo", ConfigItem.set("bar"))));
		assertThat("incorrect toString", ac.toString(), is(
				"AuthConfigSet [cfg=AuthConfig [loginAllowed=false, providers={}, " +
				"tokenLifetimeMS={DEV=350000}], " +
				"extcfg=This is a very poor toString() implementation. Sad!]"));
	}
	
	@Test
	public void configSetConstructFail() throws Exception {
		failConstructConfigSet(null, new TestExtCfg(), "cfg");
		failConstructConfigSet(new AuthConfig(true, null, null), null, "extcfg");
	}
	
	@Test
	public void configSetEquals() {
		EqualsVerifier.forClass(AuthConfigSet.class).usingGetClass().verify();
	}
	
	private void failConstructConfigSet(
			final AuthConfig ac,
			final ExternalConfig ec,
			final String exception) {
		try {
			new AuthConfigSet<>(ac, ec);
			fail("created bad config set");
		} catch (NullPointerException e) {
			assertThat("incorrect exception message", e.getMessage(), is(exception));
		}
	}
	
	@Test
	public void configSetWithUpdateEquals() {
		EqualsVerifier.forClass(AuthConfigSetWithUpdateTime.class).usingGetClass().verify();
	}
	
	@Test
	public void configSetWithUpdateConstructAndGetters() throws Exception {
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		lts.put(TokenLifetimeType.DEV, 350000L);
		final AuthConfig cfg = new AuthConfig(false, null, lts);
		final AuthConfigSetWithUpdateTime<TestExtCfg> ac =
				new AuthConfigSetWithUpdateTime<TestExtCfg>(cfg, new TestExtCfg(), -1);
		assertThat("incorrect config login", ac.getCfg().isLoginAllowed(), is(false));
		assertThat("incorrect config providers", ac.getCfg().getProviders(), is(new HashMap<>()));
		assertThat("incorrect config token lifetimes", ac.getCfg().getTokenLifetimeMS(),
				is(lts));
		assertThat("incorrect ext config", ac.getExtcfg().toMap(),
				is(ImmutableMap.of("foo", ConfigItem.set("bar"))));
		assertThat("incorrect update time", ac.getUpdateTimeInMillis(), is(-1));
	}
}
