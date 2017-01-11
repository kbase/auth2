package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

import us.kbase.auth2.lib.AuthConfig;
import us.kbase.auth2.lib.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.AuthConfig.TokenLifetimeType;
import us.kbase.test.auth2.TestCommon;

public class AuthConfigTest {

	
	@Test
	public void defaults() throws Exception {
		assertThat("incorrect login default", AuthConfig.DEFAULT_LOGIN_ALLOWED, is(false));
		assertThat("incorrect provider enabled default",
				AuthConfig.DEFAULT_PROVIDER_CONFIG.isEnabled(), is(false));
		assertThat("incorrect provider force link default",
				AuthConfig.DEFAULT_PROVIDER_CONFIG.isForceLinkChoice(), is(false));
		final Map<TokenLifetimeType, Long> defaultLifeTimes = new HashMap<>();
		defaultLifeTimes.put(TokenLifetimeType.LOGIN, 14 * 24 * 60 * 60 * 1000L);
		defaultLifeTimes.put(TokenLifetimeType.DEV, 90 * 24 * 60 * 60 * 1000L);
		defaultLifeTimes.put(TokenLifetimeType.SERV, 99_999_999_999L * 24 * 60 * 60 * 1000L);
		defaultLifeTimes.put(TokenLifetimeType.EXT_CACHE, 5 * 60 * 1000L);
		assertThat("incorrect token lifetimes", AuthConfig.DEFAULT_TOKEN_LIFETIMES_MS,
				is(defaultLifeTimes));
	}
	
	@Test
	public void providerConfig() throws Exception {
		final ProviderConfig pc = new ProviderConfig(false, true);
		assertThat("incorrect enabled", pc.isEnabled(), is(false));
		assertThat("incorrect force link", pc.isForceLinkChoice(), is(true));
		assertThat("incorrect to string", pc.toString(),
				is("ProviderConfig [enabled=false, forceLinkChoice=true]"));
		
		final ProviderConfig pc2 = new ProviderConfig(null, null);
		assertThat("incorrect enabled", pc2.isEnabled(), is((Boolean) null));
		assertThat("incorrect force link", pc2.isForceLinkChoice(), is((Boolean) null));
		assertThat("incorrect to string", pc2.toString(),
				is("ProviderConfig [enabled=null, forceLinkChoice=null]"));
	}
	
	@Test
	public void constructAndGettersSuccess() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put("pc1", new ProviderConfig(null, true));
		pc.put("pc2", new ProviderConfig(false, false));
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
		assertThat("incorrect provider force link",
				ac.getProviderConfig("pc1").isForceLinkChoice(), is(true));
		assertThat("incorrect provider enabled", ac.getProviderConfig("pc2").isEnabled(),
				is(false));
		assertThat("incorrect provider force link",
				ac.getProviderConfig("pc2").isForceLinkChoice(), is(false));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.EXT_CACHE),
				is(5 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.LOGIN),
				is(70000000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.DEV),
				is(500000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.SERV),
				is(8639999999913600000L));
		assertThat("incorrect to string", ac.toString(), is(
				"AuthConfig [loginAllowed=false, providers={pc1=ProviderConfig [enabled=null, " +
				"forceLinkChoice=true], pc2=ProviderConfig [enabled=false, " +
				"forceLinkChoice=false]}, tokenLifetimeMS={LOGIN=70000000, DEV=500000}]"));
	}
	
	@Test
	public void constructAndGettersWithNullsSuccess() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		
		final AuthConfig ac = new AuthConfig(null, null, null);
		final Map<TokenLifetimeType, Long> ltscopy = new HashMap<>(lts);
		final Map<String, ProviderConfig> pccopy = new HashMap<>(pc);
		// modify input maps to ensure does not modify config instance
		pc.put("foo", new ProviderConfig(null, null));
		lts.put(TokenLifetimeType.EXT_CACHE, 6000000L);
		
		assertThat("incorrect login allowed", ac.isLoginAllowed(), is((Boolean) null));
		assertThat("incorrect providers", ac.getProviders(), is(pccopy));
		assertThat("incorrect lifetimes", ac.getTokenLifetimeMS(), is(ltscopy));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.EXT_CACHE),
				is(5 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.LOGIN),
				is(14 * 24 * 60 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.DEV),
				is(90 * 24 * 60 * 60 * 1000L));
		assertThat("incorrect token lifetime", ac.getTokenLifetimeMS(TokenLifetimeType.SERV),
				is(8639999999913600000L));
		assertThat("incorrect to string", ac.toString(), is(
				"AuthConfig [loginAllowed=null, providers={}, tokenLifetimeMS={}]"));
	}
	
	@Test
	public void getProviderFail() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put("pc1", new ProviderConfig(null, true));
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		
		final AuthConfig ac = new AuthConfig(null, pc, lts);
		failGetProvider(ac, null, "No such provider: null");
		failGetProvider(ac, "", "No such provider: ");
		failGetProvider(ac, "pc2", "No such provider: pc2");
	}

	private void failGetProvider(final AuthConfig ac, final String provider, final String err) {
		try {
			ac.getProviderConfig(provider);
			fail("got bad provider");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(), is(err));
		}
	}
	
	@Test
	public void constructFailOnProvider() throws Exception {
		final Map<String, ProviderConfig> pc = new HashMap<>();
		pc.put(null, new ProviderConfig(false, false));
		failConstruct(pc, null, new IllegalArgumentException(
				"provider names cannot be null or empty"));
		
		pc.clear();
		pc.put("  \t  ", new ProviderConfig(null, null));
		failConstruct(pc, null, new IllegalArgumentException(
				"provider names cannot be null or empty"));
		
		pc.clear();
		pc.put("pc", null);
		failConstruct(pc, null, new NullPointerException(
				"provider config for key pc is null"));
	}
	
	@Test
	public void constructFailOnLifetimes() throws Exception {
		final Map<TokenLifetimeType, Long> lts = new HashMap<>();
		lts.put(null, 3000000L);
		failConstruct(null, lts, new NullPointerException("null key in token life time map"));
		
		lts.clear();
		lts.put(TokenLifetimeType.DEV, null);
		failConstruct(null, lts, new NullPointerException("lifetime for key DEV is null"));
		
		lts.clear();
		lts.put(TokenLifetimeType.SERV, 59999L);
		failConstruct(null, lts, new IllegalArgumentException(
				"lifetime for key SERV must be at least 60000 ms"));
	}

	private void failConstruct(
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
}
