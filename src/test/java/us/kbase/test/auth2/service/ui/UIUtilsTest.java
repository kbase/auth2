package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.TestCommon.tempToken;

import java.net.URI;
import java.net.URL;
import java.nio.file.InvalidPathException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.UUID;

import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MultivaluedHashMap;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.UriInfo;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.NoSuchEnvironmentException;
import us.kbase.auth2.lib.exceptions.NoTokenProvidedException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthExternalConfig.AuthExternalConfigMapper;
import us.kbase.auth2.service.AuthExternalConfig.URLSet;
import us.kbase.auth2.service.ui.UIUtils;
import us.kbase.test.auth2.MapBuilder;
import us.kbase.test.auth2.TestCommon;

public class UIUtilsTest {
	
	private static final Instant NOW = Instant.now();

	@Test
	public void relativizeNoCommonPathNoEndingSlash() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/whee/whoo");
		assertThat("incorrect url", UIUtils.relativize(info, "/foo/bar"), is("../foo/bar"));
	}
	
	@Test
	public void relativizeNoCommonPathWithTrailingSlash() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/whee/whoo/");
		assertThat("incorrect url", UIUtils.relativize(info, "/foo/bar/"), is("../../foo/bar/"));
	}
	
	@Test
	public void relativizeWithCommonPath() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/foo/whoo/");
		assertThat("incorrect url", UIUtils.relativize(info, "/foo/bar/"), is("../bar/"));
	}
	
	@Test
	public void relativizeGetRootParent() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/whee");
		assertThat("incorrect url", UIUtils.relativize(info, "/foo/bar/"), is("foo/bar/"));
	}
	
	@Test
	public void relativizeSamePath() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/foo/bar/");
		assertThat("incorrect url", UIUtils.relativize(info, "/foo/bar"), is(""));
	}
	
	@Test
	public void relativizeSamePathTrailingSlash() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/foo/bar/");
		assertThat("incorrect url", UIUtils.relativize(info, "/foo/bar/"), is(""));
	}
	
	@Test
	public void relativizeRootPaths() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/");
		assertThat("incorrect url", UIUtils.relativize(info, "/"), is(""));
	}
	
	@Test
	public void relativizeSubElement() {
		final UriInfo info = mock(UriInfo.class);
		when(info.getPath()).thenReturn("/foo/bar");
		assertThat("incorrect url", UIUtils.relativize(info, "/foo/baz"), is("baz"));
	}
	
	@Test
	public void relativizeFailNulls() {
		failRelativize(null, "whee", new NullPointerException("current"));
		failRelativize(mock(UriInfo.class), null, new NullPointerException("target"));
	}
	
	@Test
	public void relativizeFailIllegalPath() {
		failRelativize(mock(UriInfo.class), "/foo/bar\0baz/whee",
				new InvalidPathException("/foo/bar\0baz/whee", "Nul character not allowed"));
	}
	
	@Test
	public void relativizeFailRelativePath() {
		failRelativize(mock(UriInfo.class), "foo/bar",
				new IllegalArgumentException("target must be absolute: foo/bar"));
	}
	
	private void failRelativize(
			final UriInfo uriInfo,
			final String target,
			final Exception e) {
		try {
			UIUtils.relativize(uriInfo, target);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void removeLoginCookie() throws Exception {
		final NewCookie c = UIUtils.removeLoginCookie("name");
		
		final NewCookie expected = new NewCookie(
				"name", "no token", "/", null, "authtoken", 0, false);
		assertThat("incorrect cookie", c, is(expected));
	}
	
	@Test
	public void removeLoginCookieFailNullAndEmpty() {
		failRemoveLoginCookie(null, new IllegalArgumentException(
				"cookieName cannot be null or whitespace only"));
		failRemoveLoginCookie("  \t  \n   ",
				new IllegalArgumentException("cookieName cannot be null or whitespace only"));
	}
	
	private void failRemoveLoginCookie(final String name, final Exception e) {
		try {
			UIUtils.removeLoginCookie(name);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getLoginCookie() throws Exception {
		final NewToken t = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.now().plusSeconds(1000))
				.build(),
				"foobar");
		
		final NewCookie c = UIUtils.getLoginCookie("name", t, false);
		
		final NewCookie expected = new NewCookie(
				"name", "foobar", "/", null, "authtoken", c.getMaxAge(), false);
		assertThat("incorrect cookie less max age", c, is(expected));
		TestCommon.assertCloseTo(c.getMaxAge(), 1000, 10);
	}
	
	@Test
	public void getLoginCookieSession() throws Exception {
		final NewToken t = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.now().plusSeconds(1000))
				.build(),
				"foobar");
		
		final NewCookie c = UIUtils.getLoginCookie("name", t, true);
		
		final NewCookie expected = new NewCookie(
				"name", "foobar", "/", null, "authtoken", -1, false);
		assertThat("incorrect cookie", c, is(expected));
	}
	
	@Test
	public void getLoginCookieMaxInt() throws Exception {
		final NewToken t = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000),
						Instant.now().plusSeconds(2L * Integer.MAX_VALUE))
				.build(),
				"foobar");
		
		final NewCookie c = UIUtils.getLoginCookie("name", t, false);
		
		final NewCookie expected = new NewCookie(
				"name", "foobar", "/", null, "authtoken", Integer.MAX_VALUE, false);
		assertThat("incorrect cookie", c, is(expected));
	}
	
	@Test
	public void getLoginCookieAlreadyExpired() throws Exception {
		final NewToken t = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(30000))
				.build(),
				"foobar");
		
		final NewCookie c = UIUtils.getLoginCookie("name", t, false);
		
		final NewCookie expected = new NewCookie(
				"name", "foobar", "/", null, "authtoken", 0, false);
		assertThat("incorrect cookie", c, is(expected));
	}
	
	@Test
	public void getLoginCookieRemove() throws Exception {
		final NewCookie c = UIUtils.getLoginCookie("name", null, false);
		
		final NewCookie expected = new NewCookie(
				"name", "no token", "/", null, "authtoken", 0, false);
		assertThat("incorrect cookie", c, is(expected));
	}
	
	@Test
	public void getLoginCookieFailNoName() {
		failGetLoginCookie(null, null,
				new IllegalArgumentException("cookieName cannot be null or whitespace only"));
		failGetLoginCookie("  \t  \n   ", null,
				new IllegalArgumentException("cookieName cannot be null or whitespace only"));
	}
	
	@Test
	public void getLoginCookieFailNotLoginToken() throws Exception {
		final NewToken t = new NewToken(StoredToken.getBuilder(
				TokenType.AGENT, UUID.randomUUID(), new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(30000))
				.build(),
				"foobar");
		
		failGetLoginCookie("foo", t, new IllegalArgumentException("token must be a login token"));
	}
	
	private void failGetLoginCookie(
			final String cookieName,
			final NewToken token,
			final Exception e) {
		try {
			UIUtils.getLoginCookie(cookieName, token, false);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
			
		}
	}
	
	@Test
	public void getLoginInProcessToken() throws Exception {
		final TemporaryToken tt = tempToken(UUID.randomUUID(), NOW, 10000, "whee");
		final NewCookie nc = UIUtils.getLoginInProcessCookie(tt);
		assertThat("incorrect cookie", nc, is(new NewCookie("in-process-login-token", "whee",
				"/login", null, "logintoken", -1, false)));
	}
	
	@Test
	public void removeLoginInProcessToken() throws Exception {
		final NewCookie nc = UIUtils.getLoginInProcessCookie(null);
		assertThat("incorrect cookie", nc, is(new NewCookie("in-process-login-token", "no token",
				"/login", null, "logintoken", 0, false)));
	}
	
	@Test
	public void getLinkInProcessToken() throws Exception {
		final TemporaryToken tt = tempToken(UUID.randomUUID(), NOW, 10000, "whee");
		final NewCookie nc = UIUtils.getLinkInProcessCookie(tt);
		assertThat("incorrect cookie", nc, is(new NewCookie("in-process-link-token", "whee",
				"/link", null, "linktoken", -1, false)));
	}
	
	@Test
	public void removeLinkInProcessToken() throws Exception {
		final NewCookie nc = UIUtils.getLinkInProcessCookie(null);
		assertThat("incorrect cookie", nc, is(new NewCookie("in-process-link-token", "no token",
				"/link", null, "linktoken", 0, false)));
	}
	
	@Test
	public void getEnvironmentToken() throws Exception {
		final NewCookie nc = UIUtils.getEnvironmentCookie("env1", "/foo", 340);
		assertThat("incorrect cookie", nc, is(new NewCookie("environment", "env1",
				"/foo", null, "environment", 340, false)));
	}
	
	@Test
	public void getEnvironmentRemove() throws Exception {
		final NewCookie nc = UIUtils.getEnvironmentCookie(null, "/foo", 340);
		assertThat("incorrect cookie", nc, is(new NewCookie("environment", "no env",
				"/foo", null, "environment", 0, false)));
	}
	
	@Test
	public void getValueFromHeaderNullInput() throws Exception {
		final HttpHeaders headers = mock(HttpHeaders.class);
		when(headers.getHeaderString("myheader")).thenReturn(null);
		final Optional<String> res = UIUtils.getValueFromHeaderOrString(headers, "myheader", null);
		assertThat("incorrect value", res, is(Optional.empty()));
	}
	
	@Test
	public void getValueFromHeaderWhitespaceInput() throws Exception {
		final HttpHeaders headers = mock(HttpHeaders.class);
		when(headers.getHeaderString("myheader")).thenReturn("    \t    ");
		final Optional<String> res = UIUtils.getValueFromHeaderOrString(
				headers, "myheader", "    \t    ");
		assertThat("incorrect value", res, is(Optional.empty()));
	}
	
	@Test
	public void getValueFromHeaderHeaderValue() throws Exception {
		final HttpHeaders headers = mock(HttpHeaders.class);
		when(headers.getHeaderString("myheader")).thenReturn("       my value"    );
		final Optional<String> res = UIUtils.getValueFromHeaderOrString(
				headers, "myheader", "my other value");
		assertThat("incorrect value", res, is(Optional.of("my value")));
	}
	
	@Test
	public void getValueFromHeaderStringValue() throws Exception {
		final HttpHeaders headers = mock(HttpHeaders.class);
		when(headers.getHeaderString("myheader")).thenReturn(null);
		final Optional<String> res = UIUtils.getValueFromHeaderOrString(
				headers, "myheader", "      my other value      ");
		assertThat("incorrect value", res, is(Optional.of("my other value")));
	}
	
	@Test
	public void getValueFromHeadersFail() throws Exception {
		final HttpHeaders headers = mock(HttpHeaders.class);
		
		failGetValueFromHeader(null, "s", new NullPointerException("headers"));
		failGetValueFromHeader(headers, null, new IllegalArgumentException(
				"headerName cannot be null or whitespace only"));
		failGetValueFromHeader(headers, "    \t    ", new IllegalArgumentException(
				"headerName cannot be null or whitespace only"));
	}
	
	private void failGetValueFromHeader(
			final HttpHeaders headers,
			final String headerName,
			final Exception expected) {
		try {
			UIUtils.getValueFromHeaderOrString(headers, headerName, null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void getMaxCookieAge() throws Exception {
		final TemporaryToken tt = tempToken(
				UUID.randomUUID(), Instant.ofEpochMilli(10000),
				Instant.now().plusSeconds(1000).toEpochMilli() - 10000, "foo");
		
		TestCommon.assertCloseTo(UIUtils.getMaxCookieAge(tt), 1000, 10);
	}
	
	@Test
	public void getMaxCookieAgeMaxInt() throws Exception {
		final TemporaryToken tt = tempToken(
				UUID.randomUUID(), Instant.ofEpochMilli(10000),
				Instant.now().plusSeconds(2L * Integer.MAX_VALUE).toEpochMilli(), "foo");
		
		assertThat("incorrect cookie age", UIUtils.getMaxCookieAge(tt), is(Integer.MAX_VALUE));
	}
	
	@Test
	public void getMaxCookieAgeAlreadyExpired() throws Exception {
		final TemporaryToken tt = tempToken(
				UUID.randomUUID(), Instant.ofEpochMilli(10000), 30000, "foo");
		
		assertThat("incorrect cookie age", UIUtils.getMaxCookieAge(tt), is(0));
	}
	
	@Test
	public void getMaxCookieAgeFailNull() {
		try {
			UIUtils.getMaxCookieAge(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
	@Test
	public void getTokenFromCookie() throws Exception {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(ImmutableMap.of(
				"cookiename", new Cookie("cookiename", "  \t whee   ")));
		
		final IncomingToken t = UIUtils.getTokenFromCookie(h, "cookiename");
		assertThat("incorrect token", t, is(new IncomingToken("whee")));
	}
	
	@Test
	public void getTokenFromCookieFailBadInput() {
		failGetTokenFromCookie(null, "foo", new NullPointerException("headers"));
		failGetTokenFromCookie(mock(HttpHeaders.class), null,
				new IllegalArgumentException("tokenCookieName cannot be null or whitespace only"));
		failGetTokenFromCookie(mock(HttpHeaders.class), "   \t    \n  ",
				new IllegalArgumentException("tokenCookieName cannot be null or whitespace only"));
	}
	
	@Test
	public void getTokenFromCookieFailNoCookie() {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(
				MapBuilder.<String, Cookie>newHashMap().with("cookiename", null).build());
		
		failGetTokenFromCookie(h, "cookiename",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getTokenFromCookieFailNullCookieValue() {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(ImmutableMap.of("cookiename",
				new Cookie("cookiename", null)));
		
		failGetTokenFromCookie(h, "cookiename",
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getTokenFromCookieFailEmptyCookieValue() {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(ImmutableMap.of("cookiename",
				new Cookie("cookiename", "   \t    \n  ")));
		
		failGetTokenFromCookie(h, "cookiename",
				new NoTokenProvidedException("No user token provided"));
	}
	
	public void failGetTokenFromCookie(
			final HttpHeaders headers,
			final String cookieName,
			final Exception e) {
		try {
			UIUtils.getTokenFromCookie(headers, cookieName);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getTokenFromCookie3Arg() throws Exception {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(ImmutableMap.of(
				"cookiename", new Cookie("cookiename", "  \t whee   ")));
		
		final Optional<IncomingToken> t = UIUtils.getTokenFromCookie(h, "cookiename", true);
		assertThat("incorrect token", t, is(Optional.of(new IncomingToken("whee"))));
		final Optional<IncomingToken> t2 = UIUtils.getTokenFromCookie(h, "cookiename", false);
		assertThat("incorrect token", t2, is(Optional.of(new IncomingToken("whee"))));
	}
	
	@Test
	public void getTokenFromCookie3ArgFailBadInput() {
		failGetTokenFromCookie(null, "foo", false, new NullPointerException("headers"));
		failGetTokenFromCookie(mock(HttpHeaders.class), null, false, 
				new IllegalArgumentException("tokenCookieName cannot be null or whitespace only"));
		failGetTokenFromCookie(mock(HttpHeaders.class), "   \t    \n  ", false,
				new IllegalArgumentException("tokenCookieName cannot be null or whitespace only"));
	}
	
	@Test
	public void getTokenFromCookie3ArgNoCookie() throws Exception {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(
				MapBuilder.<String, Cookie>newHashMap().with("cookiename", null).build());
		
		final Optional<IncomingToken> t = UIUtils.getTokenFromCookie(h, "cookiename", false);
		assertThat("incorrect token", t, is(Optional.empty()));
	}
	
	@Test
	public void getTokenFromCookieFail3ArgNoCookie() {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(
				MapBuilder.<String, Cookie>newHashMap().with("cookiename", null).build());
		
		failGetTokenFromCookie(h, "cookiename", true,
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getTokenFromCookie3ArgNullCookieValue() throws Exception {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(
				MapBuilder.<String, Cookie>newHashMap().with(
						"cookiename", new Cookie("cookiename", null)).build());
		
		final Optional<IncomingToken> t = UIUtils.getTokenFromCookie(h, "cookiename", false);
		assertThat("incorrect token", t, is(Optional.empty()));
	}
	
	@Test
	public void getTokenFromCookie3ArgFailNullCookieValue() throws Exception {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(
				MapBuilder.<String, Cookie>newHashMap().with(
						"cookiename", new Cookie("cookiename", null)).build());
		
		failGetTokenFromCookie(h, "cookiename", true,
				new NoTokenProvidedException("No user token provided"));
	}
	
	@Test
	public void getTokenFromCookie3ArgEmptyCookieValue() throws Exception {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(
				MapBuilder.<String, Cookie>newHashMap().with(
						"cookiename", new Cookie("cookiename", "   \n  \t   ")).build());
		
		final Optional<IncomingToken> t = UIUtils.getTokenFromCookie(h, "cookiename", false);
		assertThat("incorrect token", t, is(Optional.empty()));
	}
	
	@Test
	public void getTokenFromCookie3ArgFailEmptyCookieValue() throws Exception {
		final HttpHeaders h = mock(HttpHeaders.class);
		when(h.getCookies()).thenReturn(
				MapBuilder.<String, Cookie>newHashMap().with(
						"cookiename", new Cookie("cookiename", "   \n  \t   ")).build());
		
		failGetTokenFromCookie(h, "cookiename", true,
				new NoTokenProvidedException("No user token provided"));
	}
	
	public void failGetTokenFromCookie(
			final HttpHeaders headers,
			final String cookieName,
			final boolean throwException,
			final Exception e) {
		try {
			UIUtils.getTokenFromCookie(headers, cookieName, throwException);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getRolesFromFormAllRoles() {
		final MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
		form.put("Admin", Collections.emptyList());
		form.put("CreateAdmin", Collections.emptyList());
		form.put("DevToken", Collections.emptyList());
		form.put("ServToken", Collections.emptyList());
		form.put("Root", Collections.emptyList());
		
		final Set<Role> got = UIUtils.getRolesFromForm(form);
		assertThat("incorrect roles", got, is(set(Role.ADMIN, Role.CREATE_ADMIN, Role.DEV_TOKEN,
				Role.SERV_TOKEN, Role.ROOT)));
	}
	
	@Test
	public void getRolesFromFormSomeRoles() {
		final MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
		form.put("Admin", Collections.emptyList());
		form.put("DevToken", Collections.emptyList());
		form.put("Root", Collections.emptyList());
		
		final Set<Role> got = UIUtils.getRolesFromForm(form);
		assertThat("incorrect roles", got, is(set(Role.ADMIN, Role.DEV_TOKEN, Role.ROOT)));
	}
	
	@Test
	public void getRolesFromFormNoRoles() {
		final MultivaluedMap<String, String> form = new MultivaluedHashMap<>();
		
		final Set<Role> got = UIUtils.getRolesFromForm(form);
		assertThat("incorrect roles", got, is(set()));
	}
	
	@Test
	public void getRolesFromFormFail() {
		try {
			UIUtils.getRolesFromForm(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("form"));
		}
	}
	
	@Test
	public void customRolesToListEmpty() {
		final List<Map<String, String>> res = UIUtils.customRolesToList(Collections.emptySet());
		assertThat("incorrect custom roles", res, is(Collections.emptyList()));
	}
	
	@Test
	public void customRolesToList() throws Exception {
		final List<Map<String, String>> res = UIUtils.customRolesToList(
				new TreeSet<>(set(new CustomRole("foo", "bar"), new CustomRole("whee", "whoo"))));
		assertThat("incorrect custom roles", res, is(Arrays.asList(
				ImmutableMap.of("id", "foo", "desc", "bar"),
				ImmutableMap.of("id", "whee", "desc", "whoo"))));
	}
	
	@Test
	public void customRolesToListFailNulls() throws Exception {
		failCustomRolesToList(null, new NullPointerException("roles"));
		failCustomRolesToList(set(new CustomRole("foo", "bar"), null),
				new NullPointerException("null role in set"));
	}
	
	private void failCustomRolesToList(final Set<CustomRole> crs, final Exception e) {
		try {
			UIUtils.customRolesToList(crs);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	@Test
	public void getExternalURI() throws Exception {
		final Authentication auth = mock(Authentication.class);
		when(auth.getEnvironments()).thenReturn(set("foo", "bar"));
		when(auth.getExternalConfig(new AuthExternalConfigMapper(set("foo", "bar"))))
				.thenReturn(AuthExternalConfig.getBuilder(
						new URLSet<>(
								ConfigItem.state(new URL("http://whee/whoo")),
								ConfigItem.emptyState(),
								ConfigItem.emptyState(),
								ConfigItem.emptyState()),
						ConfigItem.state(false),
						ConfigItem.state(false))
						.build());
		
		final URI ret = UIUtils.getExternalConfigURI(
				auth, e -> e.getURLSet().getAllowedLoginRedirectPrefix(), "/foo");
		
		assertThat("incorrect uri", ret, is(new URI("http://whee/whoo")));
	}
	
	@Test
	public void getExternalURIEnvironment() throws Exception {
		final Authentication auth = mock(Authentication.class);
		when(auth.getEnvironments()).thenReturn(set("foo"));
		when(auth.getExternalConfig(new AuthExternalConfigMapper(set("foo"))))
				.thenReturn(AuthExternalConfig.getBuilder(
						new URLSet<>(
								ConfigItem.state(new URL("http://whee/whoo")),
								ConfigItem.emptyState(),
								ConfigItem.emptyState(),
								ConfigItem.emptyState()),
						ConfigItem.state(false),
						ConfigItem.state(false))
						.withEnvironment("foo", new URLSet<>(
								ConfigItem.emptyState(),
								ConfigItem.state(new URL("http://whee/whoa")),
								ConfigItem.emptyState(),
								ConfigItem.emptyState()))
						.build());
		
		final URI ret = UIUtils.getExternalConfigURI(
				auth, e -> e.getURLSet("foo").getCompleteLoginRedirect(), "/foo");
		
		assertThat("incorrect uri", ret, is(new URI("http://whee/whoa")));
	}
	
	@Test
	public void getExternalURIDefault() throws Exception {
		final Authentication auth = mock(Authentication.class);
		when(auth.getExternalConfig(new AuthExternalConfigMapper()))
				.thenReturn(AuthExternalConfig.getBuilder(
						new URLSet<>(
								ConfigItem.emptyState(),
								ConfigItem.state(new URL("http://whee/whoo")),
								ConfigItem.emptyState(),
								ConfigItem.emptyState()),
						ConfigItem.state(false),
						ConfigItem.state(false))
						.build());
		
		final URI ret = UIUtils.getExternalConfigURI(
				auth, e -> e.getURLSet().getAllowedLoginRedirectPrefix(), "https://foo");
		
		assertThat("incorrect uri", ret, is(new URI("https://foo")));
	}
	
	@Test
	public void getExternalURIFailBadMap() throws Exception {
		final Authentication auth = mock(Authentication.class);
		when(auth.getExternalConfig(new AuthExternalConfigMapper()))
				.thenThrow(new ExternalConfigMappingException("foo"));
		failGetExternalURIDefault(auth, e -> e.getURLSet().getAllowedLoginRedirectPrefix(), "/foo",
				new RuntimeException("Dude, like, what just happened?"));
	}
	
	@Test
	public void getExternalURIFailNoSuchEnvironment() throws Exception {
		final Authentication auth = mock(Authentication.class);
		when(auth.getEnvironments()).thenReturn(set("foo", "bar"));
		when(auth.getExternalConfig(new AuthExternalConfigMapper(set("foo", "bar"))))
				.thenReturn(AuthExternalConfig.getBuilder(
						new URLSet<>(
								ConfigItem.state(new URL("http://whee/whoo")),
								ConfigItem.emptyState(),
								ConfigItem.emptyState(),
								ConfigItem.emptyState()),
						ConfigItem.state(false),
						ConfigItem.state(false))
						.withEnvironment("foo", URLSet.emptyState())
						.withEnvironment("bar", URLSet.emptyState())
						.build());
		
		failGetExternalURIDefault(auth, e -> e.getURLSet("baz").getAllowedLoginRedirectPrefix(),
				"/foo", new NoSuchEnvironmentException("baz"));
	}
	
	@Test
	public void getExternalURIFailBadArgs() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final UIUtils.ExteralConfigURLSelector selector =
				e -> e.getURLSet().getAllowedLoginRedirectPrefix();
		final String deflt = "https://foo";
		
		failGetExternalURIDefault(null, selector, deflt, new NullPointerException("auth"));
		failGetExternalURIDefault(auth, null, deflt, new NullPointerException("selector"));
		failGetExternalURIDefault(auth, selector, null,
				new IllegalArgumentException("deflt cannot be null or whitespace only"));
		failGetExternalURIDefault(auth, selector, "  \t   \n   ",
				new IllegalArgumentException("deflt cannot be null or whitespace only"));
	}
	
	private void failGetExternalURIDefault(
			final Authentication auth,
			final UIUtils.ExteralConfigURLSelector selector,
			final String deflt,
			final Exception e) {
		try {
			UIUtils.getExternalConfigURI(auth, selector, deflt);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private static final String ERR = "The javadoc explicitly said you can't pass " +
			"an invalid URI into this function, and you did it anyway. Good job.";
	
	@Test
	public void toURIFromURL() throws Exception {
		assertThat("incorrect uri", UIUtils.toURI(new URL("https://foo")),
				is(new URI("https://foo")));
	}
	
	@Test
	public void toURIfromURLFail() throws Exception {
		try {
			UIUtils.toURI(new URL("https://foo?b^r=baz"));
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new RuntimeException(ERR));
		}
	}
	
	@Test
	public void toURIFromString() throws Exception {
		assertThat("incorrect uri", UIUtils.toURI("https://foo"),
				is(new URI("https://foo")));
	}
	
	@Test
	public void toURIfromStringFail() throws Exception {
		try {
			UIUtils.toURI("https://foo?b^r=baz");
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new RuntimeException(ERR));
		}
	}
}
