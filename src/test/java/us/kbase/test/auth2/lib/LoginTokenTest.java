package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import static us.kbase.test.auth2.TestCommon.tempToken;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class LoginTokenTest {

	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(LoginToken.class).usingGetClass().verify();
	}
	
	@Test
	public void constructorNewToken() throws Exception {
		final Instant now = Instant.now();
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build(), "foo");
		
		final LoginToken lt = new LoginToken(nt);
		assertThat("incorrect isLoggedIn", lt.isLoggedIn(), is(true));
		assertThat("incorrect token", lt.getToken(), is(Optional.of(nt)));
	}
	
	@Test
	public void constructorTemporaryToken() throws Exception {
		final Instant now = Instant.now();
		final TemporaryToken tt = tempToken(
				UUID.randomUUID(), now, 5000L, "baz");
		final LoginToken lt = new LoginToken(tt);
		assertThat("incorrect isLoggedIn", lt.isLoggedIn(), is(false));
		assertThat("incorrect token id", lt.getTemporaryToken().get().getId(), is(tt.getId()));
		assertThat("incorrect token id", lt.getTemporaryToken().get().getToken(), is("baz"));
		assertThat("incorrect token id", lt.getTemporaryToken().get().getCreationDate(),
				is(tt.getCreationDate()));
		assertThat("incorrect token id", lt.getTemporaryToken().get().getExpirationDate(),
				is(tt.getExpirationDate()));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstructToken((NewToken) null, new NullPointerException("token"));
		failConstructToken((TemporaryToken) null, new NullPointerException("token"));
	}
	
	private void failConstructToken(
			final NewToken t,
			final Exception e)
			throws Exception {
		try {
			new LoginToken(t);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failConstructToken(
			final TemporaryToken t,
			final Exception e)
			throws Exception {
		try {
			new LoginToken(t);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
