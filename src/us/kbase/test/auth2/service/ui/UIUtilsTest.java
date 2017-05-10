package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.file.InvalidPathException;

import javax.ws.rs.core.UriInfo;

import org.junit.Test;

import us.kbase.auth2.lib.exceptions.AuthException;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
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
	
	
}
