package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.LocalLoginResult;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;

public class LocalLoginResultTest {

	@Test
	public void constructUser() throws Exception {
		final LocalLoginResult llr = new LocalLoginResult(new UserName("foo"));
		assertThat("incorrect reset required", llr.isPwdResetRequired(), is(true));
		assertThat("incorrect username", llr.getUserName(), is(Optional.of(new UserName("foo"))));
		assertThat("incorrect token", llr.getToken(), is(Optional.empty()));
	}

	@Test
	public void constructToken() throws Exception {
		final Instant now = Instant.now();
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(5)).build(), "foo");
		final LocalLoginResult llr = new LocalLoginResult(nt);
		assertThat("incorrect reset required", llr.isPwdResetRequired(), is(false));
		assertThat("incorrect token", llr.getToken(), is(Optional.of(nt)));
		assertThat("incorrect username",  llr.getUserName(), is(Optional.empty()));
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

