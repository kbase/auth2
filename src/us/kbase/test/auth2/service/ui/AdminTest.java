package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriInfo;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.config.AuthConfig;
import us.kbase.auth2.lib.config.AuthConfig.ProviderConfig;
import us.kbase.auth2.lib.config.AuthConfig.TokenLifetimeType;
import us.kbase.auth2.lib.config.AuthConfigSetWithUpdateTime;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.ui.Admin;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.TestCommon;

public class AdminTest {
	
	// these are unit tests, not integration tests.
	
	/*  //TODO TEST finish unit tests
	 *  //TODO TEST integration tests
	 *  - but keep the integration tests as simple as possible. On the order of 1 happy path,
	 *  1 unhappy path per method.
	 */

	@Test
	public void getConfigMinimal() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		final UriInfo uriInfo = mock(UriInfo.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		when(uriInfo.getPath()).thenReturn("/admin/config/");
		
		when(auth.getConfig(eq(new IncomingToken("token")), any(AuthExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSetWithUpdateTime<AuthExternalConfig<State>>(
						new AuthConfig(false, null, null),
						new AuthExternalConfig<>(
								ConfigItem.emptyState(),
								ConfigItem.emptyState(),
								ConfigItem.emptyState(),
								ConfigItem.emptyState(),
								ConfigItem.emptyState(),
								ConfigItem.emptyState()),
						45000));
		
		assertThat("incorrect config", admin.getConfig(headers, uriInfo), is(MapBuilder.newHashMap()
				.with("updatetimesec", 45)
				.with("allowlogin", false)
				.with("allowedloginredirect", null)
				.with("completeloginredirect", null)
				.with("completelinkredirect", null)
				.with("postlinkredirect", null)
				.with("ignoreip", false)
				.with("showstack", false)
				.with("tokenlogin", 14L)
				.with("tokenagent", 7L)
				.with("tokendev", 90L)
				.with("tokenserv", 100000000L)
				.with("tokensugcache", 5L)
				.with("providers", Collections.emptyList())
				.with("tokenurl", "token")
				.with("cfgbasicurl", "basic")
				.with("providerurl", "provider")
				.with("reseturl", "reset")
				.build()));
	}
	
	@Test
	public void getConfigMaximal() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		final UriInfo uriInfo = mock(UriInfo.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		 // this should never actually happen, but why not test it
		when(uriInfo.getPath()).thenReturn("/admin/config/token/");
		
		when(auth.getConfig(eq(new IncomingToken("token")), any(AuthExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSetWithUpdateTime<AuthExternalConfig<State>>(
						new AuthConfig(
								true,
								ImmutableMap.of(
										"prov1", new ProviderConfig(false, false, false),
										"prov2", new ProviderConfig(true, true, true)),
								ImmutableMap.of(
										TokenLifetimeType.AGENT, 1000 * 24 * 3600 * 8L,
										TokenLifetimeType.DEV, 1000 * 24 * 3600 * 42L,
										TokenLifetimeType.EXT_CACHE, 1000 * 60 * 7L,
										TokenLifetimeType.LOGIN, 1000 * 24 * 3600 * 84L,
										TokenLifetimeType.SERV, 1000 * 24 * 3600 * 2L
								)),
						new AuthExternalConfig<>(
								ConfigItem.state(new URL("http://u1.com")),
								ConfigItem.state(new URL("http://u2.com")),
								ConfigItem.state(new URL("http://u3.com")),
								ConfigItem.state(new URL("http://u4.com")),
								ConfigItem.state(true),
								ConfigItem.state(true)),
						52000));
		
		assertThat("incorrect config", admin.getConfig(headers, uriInfo), is(MapBuilder.newHashMap()
				.with("updatetimesec", 52)
				.with("allowlogin", true)
				.with("allowedloginredirect", new URL("http://u1.com"))
				.with("completeloginredirect", new URL("http://u2.com"))
				.with("completelinkredirect", new URL("http://u4.com"))
				.with("postlinkredirect", new URL("http://u3.com"))
				.with("ignoreip", true)
				.with("showstack", true)
				.with("tokenlogin", 84L)
				.with("tokenagent", 8L)
				.with("tokendev", 42L)
				.with("tokenserv", 2L)
				.with("tokensugcache", 7L)
				.with("providers", Arrays.asList(
						ImmutableMap.of(
								"provider", "prov1",
								"enabled", false,
								"forceloginchoice", false,
								"forcelinkchoice", false),
						ImmutableMap.of(
								"provider", "prov2",
								"enabled", true,
								"forceloginchoice", true,
								"forcelinkchoice", true)
						))
				.with("tokenurl", "")
				.with("cfgbasicurl", "../basic")
				.with("providerurl", "../provider")
				.with("reseturl", "../reset")
				.build()));
	}
	
	@Test
	public void getConfigFailNoTokenProvided() {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		final UriInfo uriInfo = mock(UriInfo.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie2", new Cookie("kbcookie", "token")));
		
		failGetConfig(admin, headers, uriInfo,
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getConfigFailMapping() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		final UriInfo uriInfo = mock(UriInfo.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		when(auth.getConfig(eq(new IncomingToken("token")), any(AuthExternalConfigMapper.class)))
				.thenThrow(new ExternalConfigMappingException("foo"));
		
		failGetConfig(admin, headers, uriInfo,
				new RuntimeException("There's something very wrong in the database config"));
	}
	
	@Test
	public void getConfigFailUnauthorized() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		final UriInfo uriInfo = mock(UriInfo.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		when(auth.getConfig(eq(new IncomingToken("token")), any(AuthExternalConfigMapper.class)))
				.thenThrow(new UnauthorizedException("foo"));
		
		failGetConfig(admin, headers, uriInfo, new UnauthorizedException("foo"));
	}
	
	private void failGetConfig(
			final Admin admin,
			final HttpHeaders headers,
			final UriInfo uriInfo,
			final Exception expected) {
		try {
			admin.getConfig(headers, uriInfo);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
}
