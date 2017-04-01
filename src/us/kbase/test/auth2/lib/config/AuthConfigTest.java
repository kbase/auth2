package us.kbase.test.auth2.lib.config;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfigSet;
import us.kbase.auth2.lib.config.ConfigAction.Action;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.config.ExternalConfig;
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
		
		final ProviderConfig pc2 = new ProviderConfig(null, null, null);
		assertThat("incorrect enabled", pc2.isEnabled(), is((Boolean) null));
		assertThat("incorrect force login", pc2.isForceLoginChoice(), is((Boolean) null));
		assertThat("incorrect force link", pc2.isForceLinkChoice(), is((Boolean) null));
		assertThat("incorrect to string", pc2.toString(),
				is("ProviderConfig [enabled=null, forceLoginChoice=null, forceLinkChoice=null]"));
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
		pc.put("pc1", new ProviderConfig(null, true, false));
		pc.put("pc2", new ProviderConfig(false, false, null));
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
				is((Boolean) null));
		assertThat("incorrect provider force login",
				ac.getProviderConfig("pc1").isForceLoginChoice(), is(true));
		assertThat("incorrect provider force link",
				ac.getProviderConfig("pc1").isForceLinkChoice(), is(false));
		assertThat("incorrect provider enabled", ac.getProviderConfig("pc2").isEnabled(),
				is(false));
		assertThat("incorrect provider force login",
				ac.getProviderConfig("pc2").isForceLoginChoice(), is(false));
		assertThat("incorrect provider force link",
				ac.getProviderConfig("pc2").isForceLinkChoice(), is((Boolean) null));
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
				"pc1=ProviderConfig [enabled=null, forceLoginChoice=true, " +
						"forceLinkChoice=false], " +
				"pc2=ProviderConfig [enabled=false, forceLoginChoice=false, " +
				"forceLinkChoice=null]}, tokenLifetimeMS={LOGIN=70000000, DEV=500000}]"));
	}
	
	@Test
	public void constructAndGettersWithNullsSuccess() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		
		final AuthConfig ac = new AuthConfig(null, null, null);
		final Map<TokenLifetimeType, Long> ltscopy = new HashMap<>(lts);
		final Map<String, ProviderConfig> pccopy = new HashMap<>(pc);
		// modify input maps to ensure does not modify config instance
		pc.put("foo", new ProviderConfig(null, null, null));
		lts.put(TokenLifetimeType.EXT_CACHE, 6000000L);
		
		assertThat("incorrect login allowed", ac.isLoginAllowed(), is((Boolean) null));
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
				"AuthConfig [loginAllowed=null, providers={}, tokenLifetimeMS={}]"));
	}
	
	@Test
	public void getProviderFail() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put("pc1", new ProviderConfig(null, true, false));
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		
		final AuthConfig ac = new AuthConfig(null, pc, lts);
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
		pc.put("  \t  ", new ProviderConfig(null, null, null));
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
			new AuthConfig(null, providers, lifetimes);
			fail("created bad config");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	class TestExtCfg implements ExternalConfig {

		@Override
		public Map<String, ConfigItem<String, Action>> toMap() {
			return ImmutableMap.of("foo", ConfigItem.set("bar"));
		}
		
		@Override
		public String toString() {
			return "This is a very poor toString() implementation. Sad!";
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
		failConstructConfigSet(new AuthConfig(null, null, null), null, "extcfg");
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
}
