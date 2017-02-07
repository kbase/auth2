package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;

public class LoginTokenTest {

	@Test
	public void constructorNewToken() throws Exception {
		final NewToken nt = new NewToken(TokenType.EXTENDED_LIFETIME, "foo", new UserName("bar"),
				10000);
		final LoginToken lt = new LoginToken(nt);
		assertThat("incorrect isLoggedIn", lt.isLoggedIn(), is(true));
		assertThat("incorrect token type", lt.getToken().getTokenType(),
				is(TokenType.EXTENDED_LIFETIME));
		assertThat("incorrect creation date", lt.getToken().getCreationDate(),
				is(nt.getCreationDate()));
		assertThat("incorrect expiration date", lt.getToken().getExpirationDate(),
				is(nt.getExpirationDate()));
		assertThat("incorrect token id", lt.getToken().getId(), is(nt.getId()));
		assertThat("incorrect token", lt.getToken().getToken(), is("foo"));
		assertThat("incorrect token name", lt.getToken().getTokenName(), is((String) null));
		assertThat("incorrect token username", lt.getToken().getUserName(),
				is(new UserName("bar")));
	}
	
	@Test
	public void constructorTemporaryToken() throws Exception {
		final TemporaryToken tt = new TemporaryToken("baz", 5000);
		final LoginToken lt = new LoginToken(tt);
		assertThat("incorrect isLoggedIn", lt.isLoggedIn(), is(false));
		assertThat("incorrect token id", lt.getTemporaryToken().getId(), is(tt.getId()));
		assertThat("incorrect token id", lt.getTemporaryToken().getToken(), is("baz"));
		assertThat("incorrect token id", lt.getTemporaryToken().getCreationDate(),
				is(tt.getCreationDate()));
		assertThat("incorrect token id", lt.getTemporaryToken().getExpirationDate(),
				is(tt.getExpirationDate()));
	}
	
	@Test
	public void constructFailToken() throws Exception {
		try {
			new LoginToken((NewToken) null);
			fail("expected exception");
		} catch (NullPointerException npe) {
			assertThat("incorrect exception message", npe.getMessage(), is("token"));
		}
	}
	
	@Test
	public void constructFailTempToken() throws Exception {
		try {
			new LoginToken((TemporaryToken) null);
			fail("expected exception");
		} catch (NullPointerException npe) {
			assertThat("incorrect exception message", npe.getMessage(), is("token"));
		}
	}
}
