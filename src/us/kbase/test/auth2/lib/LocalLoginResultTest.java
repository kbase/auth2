package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.LocalLoginResult;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TokenType;

public class LocalLoginResultTest {

	@Test
	public void constructUser() throws Exception {
		final LocalLoginResult llr = new LocalLoginResult(new UserName("foo"));
		assertThat("incorrect reset required", llr.isPwdResetRequired(), is(true));
		assertThat("incorrect username", llr.getUserName(), is(Optional.of(new UserName("foo"))));
		assertThat("incorrect token", llr.getToken(), is(Optional.absent()));
	}

	@Test
	public void constructToken() throws Exception {
		final NewToken nt = new NewToken(UUID.randomUUID(),
				TokenType.LOGIN, "foo", new UserName("bar"), Instant.now(), 5000);
		final LocalLoginResult llr = new LocalLoginResult(nt);
		assertThat("incorrect reset required", llr.isPwdResetRequired(), is(false));
		final NewToken got = llr.getToken().get();
		assertThat("incorrect token type", got.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect creation date", got.getCreationDate(),
				is(nt.getCreationDate()));
		assertThat("incorrect expiration date", got.getExpirationDate(),
				is(nt.getExpirationDate()));
		assertThat("incorrect token id", got.getId(), is(nt.getId()));
		assertThat("incorrect token", got.getToken(), is("foo"));
		assertThat("incorrect token name", got.getTokenName(), is(Optional.absent()));
		assertThat("incorrect token username", got.getUserName(),
				is(new UserName("bar")));
		
		assertThat("incorrect username",  llr.getUserName(), is(Optional.absent()));
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

