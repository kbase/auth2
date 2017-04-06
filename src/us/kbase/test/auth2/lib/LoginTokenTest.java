package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LoginState;
import us.kbase.auth2.lib.LoginToken;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;

public class LoginTokenTest {

	private static final RemoteIdentity REMOTE = new RemoteIdentity(
			new RemoteIdentityID("foo", "bar42"),
			new RemoteIdentityDetails("user42", "full42", "email42"));
	
	private static final LoginState LOGIN_STATE;
	static {
		try {
			LOGIN_STATE = LoginState.getBuilder("foo", false).withUser(
					NewUser.getBuilder(
							new UserName("foo"), new DisplayName("bar"), Instant.now(), REMOTE)
							.withEmailAddress(new EmailAddress("f@g.com")).build(),
					REMOTE)
					.withExpires(Instant.ofEpochMilli(70000))
					.build();
		} catch (Exception e) {
			throw new RuntimeException("Fix yer tests nub", e);
		}
	}
	
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
		
		final LoginToken lt = new LoginToken(nt, LOGIN_STATE);
		assertThat("incorrect isLoggedIn", lt.isLoggedIn(), is(true));
		assertThat("incorrect token", lt.getToken(), is(nt));
		assertThat("incorrect login state provider", lt.getLoginState().getProvider(), is("foo"));
		assertThat("incorrect login state login allowed",
				lt.getLoginState().isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect login state expires", lt.getLoginState().getExpires(),
				is(Optional.absent()));
	}
	
	@Test
	public void constructorTemporaryToken() throws Exception {
		final Instant now = Instant.now();
		final TemporaryToken tt = new TemporaryToken(
				UUID.randomUUID(), "baz", now, 5000);
		final LoginToken lt = new LoginToken(tt, LOGIN_STATE);
		assertThat("incorrect isLoggedIn", lt.isLoggedIn(), is(false));
		assertThat("incorrect token id", lt.getTemporaryToken().getId(), is(tt.getId()));
		assertThat("incorrect token id", lt.getTemporaryToken().getToken(), is("baz"));
		assertThat("incorrect token id", lt.getTemporaryToken().getCreationDate(),
				is(tt.getCreationDate()));
		assertThat("incorrect token id", lt.getTemporaryToken().getExpirationDate(),
				is(tt.getExpirationDate()));
		assertThat("incorrect login state provider", lt.getLoginState().getProvider(), is("foo"));
		assertThat("incorrect login state login allowed",
				lt.getLoginState().isNonAdminLoginAllowed(), is(false));
		assertThat("incorrect login state expires", lt.getLoginState().getExpires(),
				is(Optional.of(now.plusMillis(5000))));
	}
	
	@Test
	public void constructFail() throws Exception {
		final Instant now = Instant.now();
		final NewToken nt = new NewToken(StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), new UserName("bar"))
			.withLifeTime(now, now.plusSeconds(10)).build(), "foo");

		failConstructToken((NewToken) null, LOGIN_STATE, new NullPointerException("token"));
		failConstructToken(nt, null, new NullPointerException("loginState"));
		
		failConstructToken(nt, LoginState.getBuilder("foo", false).build(),
				new IllegalStateException("Login process is complete but user count != 1 " +
						"or unlinked identities > 0"));
		failConstructToken(nt, LoginState.getBuilder("foo", false)
				.withUser(LOGIN_STATE.getUser(new UserName("foo")), REMOTE)
				.withIdentity(REMOTE).build(),
				new IllegalStateException("Login process is complete but user count != 1 " +
						"or unlinked identities > 0"));
		
		final TemporaryToken tt = new TemporaryToken(UUID.randomUUID(),
				"baz", Instant.now(), 5000);
		failConstructToken((TemporaryToken) null, LOGIN_STATE, new NullPointerException("token"));
		failConstructToken(tt, null, new NullPointerException("loginState"));
	}
	
	private void failConstructToken(
			final NewToken t,
			final LoginState ls,
			final Exception e)
			throws Exception {
		try {
			new LoginToken(t, ls);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
	private void failConstructToken(
			final TemporaryToken t,
			final LoginState ls,
			final Exception e)
			throws Exception {
		try {
			new LoginToken(t, ls);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
