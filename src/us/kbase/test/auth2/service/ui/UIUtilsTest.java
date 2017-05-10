package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.InvalidPathException;
import java.time.Instant;
import java.util.UUID;

import javax.ws.rs.core.NewCookie;
import javax.ws.rs.core.UriInfo;

import org.junit.Test;

import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.ui.UIUtils;
import us.kbase.test.auth2.TestCommon;

public class UIUtilsTest {

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
	public void checkState() throws Exception {
		UIUtils.checkState("foo", "foo"); // expect nothing to happen
	}
	
	@Test
	public void checkStateFailNulls() {
		failCheckState(null, "foo",
				new MissingParameterException("Couldn't retrieve state value from cookie"));
		failCheckState("foo", null, new AuthException(ErrorType.AUTHENTICATION_FAILED,
				"State values do not match, this may be a CXRF attack"));
	}
	
	@Test
	public void checkStateFailNoMatch() {
		failCheckState("foo", "bar", new AuthException(ErrorType.AUTHENTICATION_FAILED,
				"State values do not match, this may be a CXRF attack"));
	}
	
	private void failCheckState(final String cookie, final String state, final Exception e) {
		try {
			UIUtils.checkState(cookie, state);
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
		failRemoveLoginCookie(null, new IllegalArgumentException("Missing argument: cookieName"));
		failRemoveLoginCookie("  \t  \n   ",
				new IllegalArgumentException("Missing argument: cookieName"));
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
				new IllegalArgumentException("Missing argument: cookieName"));
		failGetLoginCookie("  \t  \n   ", null,
				new IllegalArgumentException("Missing argument: cookieName"));
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
	public void getMaxCookieAge() {
		final TemporaryToken tt = new TemporaryToken(
				UUID.randomUUID(), "foo", Instant.ofEpochMilli(10000),
				Instant.now().plusSeconds(1000).toEpochMilli() - 10000);
		
		TestCommon.assertCloseTo(UIUtils.getMaxCookieAge(tt), 1000, 10);
	}
	
	@Test
	public void getMaxCookieAgeMaxInt() {
		final TemporaryToken tt = new TemporaryToken(
				UUID.randomUUID(), "foo", Instant.ofEpochMilli(10000),
				Instant.now().plusSeconds(2L * Integer.MAX_VALUE).toEpochMilli());
		
		assertThat("incorrect cookie age", UIUtils.getMaxCookieAge(tt), is(Integer.MAX_VALUE));
	}
	
	@Test
	public void getMaxCookieAgeAlreadyExpired() {
		final TemporaryToken tt = new TemporaryToken(
				UUID.randomUUID(), "foo", Instant.ofEpochMilli(10000), 30000);
		
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
	
}
