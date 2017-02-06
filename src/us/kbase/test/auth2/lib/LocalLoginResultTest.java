package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.LocalLoginResult;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TokenType;

public class LocalLoginResultTest {

	@Test
	public void constructUser() throws Exception {
		final LocalLoginResult llr = new LocalLoginResult(new UserName("foo"));
		assertThat("incorrect reset required", llr.isPwdResetRequired(), is(true));
		assertThat("incorrect username", llr.getUserName(), is(new UserName("foo")));
		try {
			llr.getToken();
			fail("expected exception");
		} catch (IllegalStateException e) {
			assertThat("incorrect exception message", e.getMessage(), is("no token"));
		}
	}

	@Test
	public void constructToken() throws Exception {
		final NewToken nt = new NewToken(TokenType.LOGIN, "foo", new UserName("bar"), 5000);
		final LocalLoginResult llr = new LocalLoginResult(nt);
		assertThat("incorrect reset required", llr.isPwdResetRequired(), is(false));
		assertThat("incorrect token type", llr.getToken().getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect creation date", llr.getToken().getCreationDate(),
				is(nt.getCreationDate()));
		assertThat("incorrect expiration date", llr.getToken().getExpirationDate(),
				is(nt.getExpirationDate()));
		assertThat("incorrect token id", llr.getToken().getId(), is(nt.getId()));
		assertThat("incorrect token", llr.getToken().getToken(), is("foo"));
		assertThat("incorrect token name", llr.getToken().getTokenName(), is((String) null));
		assertThat("incorrect username", llr.getToken().getUserName(), is(new UserName("bar")));
		try {
			llr.getUserName();
			fail("expected exception");
		} catch (IllegalStateException e) {
			assertThat("incorrect exception message", e.getMessage(), is("no username"));
		}
	}
	
	@Test
	public void constructFailToken() throws Exception {
		try {
			new LocalLoginResult((NewToken) null);
			fail("expected exception");
		} catch (NullPointerException npe) {
			assertThat("incorrect exception message", npe.getMessage(), is("token"));
		}
	}
	
	@Test
	public void constructFailUser() throws Exception {
		try {
			new LocalLoginResult((UserName) null);
			fail("expected exception");
		} catch (NullPointerException npe) {
			assertThat("incorrect exception message", npe.getMessage(), is("userName"));
		}
	}
}

