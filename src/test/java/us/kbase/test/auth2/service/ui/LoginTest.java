package us.kbase.test.auth2.service.ui;

import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.junit.Assert.fail;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.config.ConfigItem;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.service.AuthAPIStaticConfig;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.UserAgentParser;
import us.kbase.auth2.service.AuthExternalConfig.URLSet;
import us.kbase.auth2.service.ui.Login;
import us.kbase.testutils.TestCommon;

public class LoginTest {

	// these are unit tests, not integration tests.
	
	// TODO TEST finish unit tests
	
	// TODO TEST need to add unit tests for happy path createUser (and a lot of other stuff)
	@Test
	public void createUserFailUnderscores() throws Exception {
		final Authentication auth = mock(Authentication.class);
		final AuthAPIStaticConfig cfg = new AuthAPIStaticConfig("kbcookie", "fake");
		final HttpServletRequest hsr = mock(HttpServletRequest.class);
		final UserAgentParser uap = mock(UserAgentParser.class);  // looong startup
		
		when(hsr.getHeader("user-agent")).thenReturn("foo");
		when(uap.getTokenContextFromUserAgent("foo")).thenReturn(
				TokenCreationContext.getBuilder()
		);
		when(auth.getExternalConfig(isA(AuthExternalConfig.AuthExternalConfigMapper.class)))
			.thenReturn(AuthExternalConfig.getBuilder(
					new URLSet<>(
							ConfigItem.emptyState(),
							ConfigItem.emptyState(),
							ConfigItem.emptyState(),
							ConfigItem.emptyState()),
					ConfigItem.state(true),  // ignore ip headers
					ConfigItem.state(false))
					.build());
		when(hsr.getRemoteAddr()).thenReturn("");  // causes system to ignore IP
		
		final Login login = new Login(auth, cfg, uap);
		
		final String err = "New usernames cannot contain repeating underscores or trailing "
				+ "underscores";
		
		createLocalUserFail(
				login,
				hsr,
				"tok",
				null,
				null,
				null,
				"ident",
				"foo__bar",
				"display",
				"foo@example.com",
				new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME, err)
		);
		createLocalUserFail(
				login,
				hsr,
				"tok",
				null,
				null,
				null,
				"ident",
				"foobar_",
				"display",
				"foo@example.com",
				new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME, err)
		);
	}
	
	private void createLocalUserFail(
			final Login login,
			final HttpServletRequest req,
			final String token,
			final String redirect,
			final String session,
			final String environment,
			final String identityID,
			final String userName,
			final String displayName,
			final String email,
			final Exception expected
			) throws Exception {
		try {
			login.createUser(  // form based
					req,
					token,
					redirect,
					session,
					environment,
					identityID,
					userName,
					displayName,
					email,
					null,
					null,
					null
			);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
		try {
			login.createUser(  // json based
					req,
					token,
					redirect,
					environment,
					new Login.CreateChoice(
							identityID,
							userName,
							displayName,
							email,
							null,
							null,
							false
					)
			);
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}

}
