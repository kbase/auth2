package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static us.kbase.test.auth2.TestCommon.set;

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
import us.kbase.auth2.lib.config.AuthConfigUpdate;
import us.kbase.auth2.lib.config.ConfigAction.State;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.exceptions.UnauthorizedException;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.AuthExternalConfig.URLSet;
import us.kbase.auth2.service.ui.Admin;
import us.kbase.auth2.service.ui.Admin.SetConfig;
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
		
		when(auth.getEnvironments()).thenReturn(Collections.emptySet());
		
		when(uriInfo.getPath()).thenReturn("/admin/config/");
		
		when(auth.getConfig(eq(new IncomingToken("token")), any(AuthExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSetWithUpdateTime<AuthExternalConfig<State>>(
						new AuthConfig(false, null, null),
						AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.emptyState(),
										ConfigItem.emptyState(),
										ConfigItem.emptyState(),
										ConfigItem.emptyState()),
								ConfigItem.emptyState(),
								ConfigItem.emptyState())
						.build(),
						45000));
		
		assertThat("incorrect config", admin.getConfig(headers, uriInfo),
				is(MapBuilder.newHashMap()
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
						.with("environments", Collections.emptyList())
						.with("providers", Collections.emptyList())
						.with("tokenurl", "token")
						.with("cfgbasicurl", "basic")
						.with("providerurl", "provider")
						.with("reseturl", "reset")
						.with("environmenturl", "environment")
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
		
		when(auth.getEnvironments()).thenReturn(set("someenv", "otherenv"));
		
		 // this should never actually happen, but why not test it
		when(uriInfo.getPath()).thenReturn("/admin/config/token/");
		
		when(auth.getConfig(eq(new IncomingToken("token")), any(AuthExternalConfigMapper.class)))
				.thenReturn(new AuthConfigSetWithUpdateTime<>(
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
						AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.state(new URL("http://u1.com")),
										ConfigItem.state(new URL("http://u2.com")),
										ConfigItem.state(new URL("http://u3.com")),
										ConfigItem.state(new URL("http://u4.com"))),
								ConfigItem.state(true),
								ConfigItem.state(true))
						.withEnvironment("someenv", new URLSet<>(
								ConfigItem.state(new URL("http://u5.com")),
								ConfigItem.emptyState(),
								ConfigItem.state(new URL("http://u7.com")),
								ConfigItem.state(new URL("http://u8.com"))))
						.withEnvironment("otherenv", new URLSet<>(
								ConfigItem.state(new URL("http://u9.com")),
								ConfigItem.state(new URL("http://u10.com")),
								ConfigItem.emptyState(),
								ConfigItem.state(new URL("http://u12.com"))))
						.build(),
						52000));
		
		assertThat("incorrect config", admin.getConfig(headers, uriInfo),
				is(MapBuilder.newHashMap()
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
						.with("environments", Arrays.asList(
								MapBuilder.newHashMap()
										.with("environment", "otherenv")
										.with("allowedloginredirect", new URL("http://u9.com"))
										.with("completeloginredirect", new URL("http://u10.com"))
										.with("completelinkredirect", new URL("http://u12.com"))
										.with("postlinkredirect", null)
										.build(),
								MapBuilder.newHashMap()
										.with("environment", "someenv")
										.with("allowedloginredirect", new URL("http://u5.com"))
										.with("completeloginredirect", null)
										.with("completelinkredirect", new URL("http://u8.com"))
										.with("postlinkredirect", new URL("http://u7.com"))
										.build()))
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
						.with("environmenturl", "../environment")
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
	
	@Test
	public void updateBasicNulls() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		admin.updateBasic(headers, null, null,  null, null, null, null, null);
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withLoginAllowed(false)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove()),
								ConfigItem.set(false),
								ConfigItem.set(false)
								).build())
						.build());
	}
	
	@Test
	public void updateBasicWhitespace() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		admin.updateBasic(headers, "   \t  ", "   \t  ", "   \t  ", "   \t  ", "   \t  ",
				"   \t  ", "   \t  ");
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withLoginAllowed(false)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove()),
								ConfigItem.set(false),
								ConfigItem.set(false)
								).build())
						.build());
	}
	
	@Test
	public void updateBasicMaximal() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		admin.updateBasic(headers, "stuff", "s1", "s2", "http://u1.com", "http://u2.com",
				"http://u3.com", "http://u4.com");
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withLoginAllowed(true)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.set(new URL("http://u1.com")),
										ConfigItem.set(new URL("http://u2.com")),
										ConfigItem.set(new URL("http://u3.com")),
										ConfigItem.set(new URL("http://u4.com"))),
								ConfigItem.set(true),
								ConfigItem.set(true)
								).build())
						.build());
	}
	
	@Test
	public void updateBasicBadURL() throws Exception {
		final String g = "http://u.com";
		final String b = "htp://u.com";
		
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		failUpdateBasic(admin, headers, b, g, g, g,
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failUpdateBasic(admin, headers, g, b, g, g,
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failUpdateBasic(admin, headers, g, g, b, g,
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failUpdateBasic(admin, headers, g, g, g, b,
				new IllegalParameterException("Illegal URL: htp://u.com"));
	}
	
	@Test
	public void updateBasicBadURI() throws Exception {
		final String g = "http://u.com";
		final String b = "http://u^u.com";
		
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		failUpdateBasic(admin, headers, b, g, g, g,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failUpdateBasic(admin, headers, g, b, g, g,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failUpdateBasic(admin, headers, g, g, b, g,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failUpdateBasic(admin, headers, g, g, g, b,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
	}
	
	@Test
	public void updateBasicFailNoTokenProvided() {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie2", new Cookie("kbcookie", "token")));
		
		final String g = "http://u.com";
		
		failUpdateBasic(admin, headers, g, g, g, g,
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void updateBasicFailInvalidToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		doThrow(new InvalidTokenException()).when(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withLoginAllowed(false)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove()),
								ConfigItem.set(false),
								ConfigItem.set(false)
								).build())
						.build());
		
		failUpdateBasic(admin, headers, "", "", "", "", new InvalidTokenException());
	}
		
	private void failUpdateBasic(
			final Admin admin,
			final HttpHeaders headers,
			final String allowedloginredirect,
			final String completeloginredirect,
			final String postlinkredirect,
			final String completelinkredirect,
			final Exception expected) {
		
		try {
			admin.updateBasic(headers, "", "", "", allowedloginredirect, completeloginredirect,
					postlinkredirect, completelinkredirect);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void updateConfigNulls() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		admin.updateConfig("token", new SetConfig(null, null, null, null, null, null, null, null));
		
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withNullableLoginAllowed(null)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.noAction(),
										ConfigItem.noAction(),
										ConfigItem.noAction(),
										ConfigItem.noAction()),
								ConfigItem.noAction(),
								ConfigItem.noAction()
								).build())
						.build());
	}
	
	@Test
	public void updateConfigWhitespace() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		final String ws = "  \t    ";
		admin.updateConfig("token", new SetConfig(null, null, null, ws, ws, ws, ws, null));
		
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withNullableLoginAllowed(null)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.noAction(),
										ConfigItem.noAction(),
										ConfigItem.noAction(),
										ConfigItem.noAction()),
								ConfigItem.noAction(),
								ConfigItem.noAction()
								).build())
						.build());
	}
	
	@Test
	public void updateConfigRemove() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		admin.updateConfig("token", new SetConfig(null, null, null, null, null, null, null,
				Arrays.asList(
						"allowedloginredirect",
						"completeloginredirect",
						"completelinkredirect",
						"postlinkredirect",
						"ignoreip",
						"showstack"
						)));
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withNullableLoginAllowed(null)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove(),
										ConfigItem.remove()),
								ConfigItem.remove(),
								ConfigItem.remove()
								).build())
						.build());
	}
	
	@Test
	public void updateConfigSetTrue() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		admin.updateConfig("token", new SetConfig(true, true, true,
				"http://u1.com", "http://u2.com", "http://u3.com", "http://u4.com", null));
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withLoginAllowed(true)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.set(new URL("http://u1.com")),
										ConfigItem.set(new URL("http://u2.com")),
										ConfigItem.set(new URL("http://u3.com")),
										ConfigItem.set(new URL("http://u4.com"))),
								ConfigItem.set(true),
								ConfigItem.set(true)
								).build())
						.build());
	}
	
	@Test
	public void updateConfigSetFalse() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		admin.updateConfig("token", new SetConfig(false, false, false,
				"http://u1.com", "http://u2.com", "http://u3.com", "http://u4.com", null));
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withLoginAllowed(false)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.set(new URL("http://u1.com")),
										ConfigItem.set(new URL("http://u2.com")),
										ConfigItem.set(new URL("http://u3.com")),
										ConfigItem.set(new URL("http://u4.com"))),
								ConfigItem.set(false),
								ConfigItem.set(false)
								).build())
						.build());
	}
	
	@Test
	public void updateConfigFailNullBody() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		failUpdateConfig(admin, "t", null, new MissingParameterException("JSON body missing"));
	}
	
	@Test
	public void updateConfigFailUnexpectedProperties() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		final Boolean n = null;
		final String s = null;
		final SetConfig sc = new SetConfig(n, n, n, s, s, s, s, null);
		sc.setAdditionalProperties("foo", "bar");
		sc.setAdditionalProperties("baz", "bat");
		
		try {
			admin.updateConfig("t", sc);
			fail("expected exception");
		} catch (IllegalParameterException got) {
			final String e = "30001 Illegal input parameter: Unexpected parameters in request: ";
			assertThat("incorrect exception", got.getMessage(), anyOf(
					is(e + "foo, baz"),
					is(e + "baz, foo")));
		}
	}
	
	@Test
	public void updateConfigFailBadURL() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		final String g = "http://u.com";
		final String b = "htp://u.com";
		final Boolean n = null;
		
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, b, g, g, g, null),
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, g, b, g, g, null),
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, g, g, b, g, null),
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, g, g, g, b, null),
				new IllegalParameterException("Illegal URL: htp://u.com"));
	}
	
	@Test
	public void updateConfigFailBadURI() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		final String g = "http://u.com";
		final String b = "http://u^u.com";
		final Boolean n = null;
		
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, b, g, g, g, null),
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, g, b, g, g, null),
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, g, g, b, g, null),
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failUpdateConfig(admin, "t", new SetConfig(n, n, n, g, g, g, b, null),
				new IllegalParameterException("Illegal URL: http://u^u.com"));
	}
	
	@Test
	public void updateConfigFailNoToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		final Boolean n = null;
		final String s = null;
		final SetConfig sc = new SetConfig(n, n, n, s, s, s, s, null);
		
		failUpdateConfig(admin, null, sc,
				new NoTokenProvidedException("No user token provided"));
		failUpdateConfig(admin, "   \t  ", sc,
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void updateConfigFailInvalidToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		
		final Admin admin = new Admin(auth, cfg);
		
		doThrow(new InvalidTokenException()).when(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withNullableLoginAllowed(null)
						.withExternalConfig(AuthExternalConfig.getBuilder(
								new URLSet<>(
										ConfigItem.noAction(),
										ConfigItem.noAction(),
										ConfigItem.noAction(),
										ConfigItem.noAction()),
								ConfigItem.noAction(),
								ConfigItem.noAction()
								).build())
						.build());
		
		final Boolean n = null;
		final String s = null;
		final SetConfig sc = new SetConfig(n, n, n, s, s, s, s, null);
		
		failUpdateConfig(admin, "token", sc, new InvalidTokenException());
	}
	
	private void failUpdateConfig(
			final Admin admin,
			final String token,
			final SetConfig cfg,
			final Exception expected) {
		try {
			admin.updateConfig(token, cfg);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void configEnvironmentNulls() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		when(auth.getEnvironments()).thenReturn(set("env"));
		
		admin.configEnvironment(headers, "env", null, null, null, null);
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withExternalConfig(AuthExternalConfig.getBuilder(
								URLSet.noAction(), ConfigItem.noAction(), ConfigItem.noAction())
								.withEnvironment("env", URLSet.remove())
								.build())
						.build());
	}
	
	@Test
	public void configEnvironmentWhitespace() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(auth.getEnvironments()).thenReturn(set("env"));
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		admin.configEnvironment(headers, "env", "   \t   ", "   \t   ", "   \t   ", "   \t   ");
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withExternalConfig(AuthExternalConfig.getBuilder(
								URLSet.noAction(), ConfigItem.noAction(), ConfigItem.noAction())
								.withEnvironment("env", URLSet.remove())
								.build())
						.build());
	}
	
	@Test
	public void configEnvironmentMaximal() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(auth.getEnvironments()).thenReturn(set("env"));
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		admin.configEnvironment(headers, "env", "http://u1.com", "http://u2.com",
				"http://u3.com", "http://u4.com");
		
		verify(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withExternalConfig(AuthExternalConfig.getBuilder(
								URLSet.noAction(), ConfigItem.noAction(), ConfigItem.noAction())
								.withEnvironment("env", new URLSet<>(
										ConfigItem.set(new URL("http://u1.com")),
										ConfigItem.set(new URL("http://u2.com")),
										ConfigItem.set(new URL("http://u3.com")),
										ConfigItem.set(new URL("http://u4.com"))))
								.build())
						.build());;
	}
	
	@Test
	public void configEnvBadURL() throws Exception {
		final String g = "http://u.com";
		final String b = "htp://u.com";
		
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		when(auth.getEnvironments()).thenReturn(set("e"));
		
		final Admin admin = new Admin(auth, cfg);
		
		failConfigEnvironment(admin, headers, "e", b, g, g, g,
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failConfigEnvironment(admin, headers, "e", g, b, g, g,
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failConfigEnvironment(admin, headers, "e", g, g, b, g,
				new IllegalParameterException("Illegal URL: htp://u.com"));
		failConfigEnvironment(admin, headers, "e", g, g, g, b,
				new IllegalParameterException("Illegal URL: htp://u.com"));
	}
	
	@Test
	public void configEnvBadURI() throws Exception {
		final String g = "http://u.com";
		final String b = "http://u^u.com";
		
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		when(auth.getEnvironments()).thenReturn(set("e"));
		
		final Admin admin = new Admin(auth, cfg);
		
		failConfigEnvironment(admin, headers, "e", b, g, g, g,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failConfigEnvironment(admin, headers, "e", g, b, g, g,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failConfigEnvironment(admin, headers, "e", g, g, b, g,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
		failConfigEnvironment(admin, headers, "e", g, g, g, b,
				new IllegalParameterException("Illegal URL: http://u^u.com"));
	}

	@Test
	public void configEnvBadEnvironment() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(auth.getEnvironments()).thenReturn(set("foo"));
		
		final String g = "http://u.com";
		failConfigEnvironment(admin, headers, null, g, g, g, g, new NoSuchEnvironmentException(
				null));
		failConfigEnvironment(admin, headers, "    \t    ", g, g, g, g,
				new NoSuchEnvironmentException("    \t    "));
		failConfigEnvironment(admin, headers, "bar", g, g, g, g,
				new NoSuchEnvironmentException("bar"));
	}
	
	@Test
	public void configEnvironmentFailNoTokenProvided() {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(auth.getEnvironments()).thenReturn(set("e"));
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie2", new Cookie("kbcookie", "token")));
		
		final String g = "http://u.com";
		
		failConfigEnvironment(admin, headers, "e", g, g, g, g,
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void configEnvironmentFailInvalidToken() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie");
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		final Admin admin = new Admin(auth, cfg);
		
		when(auth.getEnvironments()).thenReturn(set("e"));
		
		when(headers.getCookies()).thenReturn(
				ImmutableMap.of("kbcookie", new Cookie("kbcookie", "token")));
		
		doThrow(new InvalidTokenException()).when(auth).updateConfig(
				new IncomingToken("token"),
				AuthConfigUpdate.getBuilder()
						.withExternalConfig(AuthExternalConfig.getBuilder(
								URLSet.noAction(), ConfigItem.noAction(), ConfigItem.noAction())
								.withEnvironment("e", URLSet.remove())
								.build())
						.build());
		
		failConfigEnvironment(admin, headers, "e", "", "", "", "", new InvalidTokenException());
	}
	
	private void failConfigEnvironment(
		final Admin admin,
		final HttpHeaders headers,
		final String environment,
		final String allowedloginredirect,
		final String completeloginredirect,
		final String postlinkredirect,
		final String completelinkredirect,
		final Exception expected) {
	
	try {
		admin.configEnvironment(headers, environment, allowedloginredirect, completeloginredirect,
				postlinkredirect, completelinkredirect);
		fail("expected exception");
	} catch (Exception got) {
		TestCommon.assertExceptionCorrect(got, expected);
	}
}
}
