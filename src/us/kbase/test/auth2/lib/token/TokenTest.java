package us.kbase.test.auth2.lib.token;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Date;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TemporaryHashedToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenType;

public class TokenTest {

	@Test
	public void tokenTypeGetType() throws Exception {
		assertThat("failed to get login token type", TokenType.getType("Login"),
				is(TokenType.LOGIN));
		assertThat("failed to get login token type", TokenType.getType("ExtLife"),
				is(TokenType.EXTENDED_LIFETIME));
		try {
			TokenType.getType(null);
			fail("got bad type");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(), is("Invalid role id: null"));
		}
	}
	
	@Test
	public void tokenTypes() throws Exception {
		assertThat("Incorrect id for login token", TokenType.LOGIN.getID(), is("Login"));
		assertThat("Incorrect description for login token", TokenType.LOGIN.getDescription(),
				is("Login"));
		assertThat("Incorrect id for ext life token", TokenType.EXTENDED_LIFETIME.getID(),
				is("ExtLife"));
		assertThat("Incorrect description for ext life token",
				TokenType.EXTENDED_LIFETIME.getDescription(), is("Extended lifetime"));
	}
	
	@Test
	public void incomingToken() throws Exception {
		final IncomingToken it = new IncomingToken("foo");
		assertThat("correct token string", it.getToken(), is("foo"));
		final IncomingHashedToken iht = it.getHashedToken();
		assertThat("correct token hash", iht.getTokenHash(),
				is("LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564="));
		
		failCreateIncomingToken("");
		failCreateIncomingToken(null);
	}

	private void failCreateIncomingToken(final String token) {
		try {
			new IncomingToken(token);
			fail("created bad incoming token");
		} catch (MissingParameterException e) {
			assertThat("correct exception message", e.getMessage(),
					is("30000 Missing input parameter: token"));
		}
	}
	
	@Test
	public void temporaryToken() throws Exception {
		final TemporaryToken tt = new TemporaryToken("foobar", 5);
		final Date now = new Date();
		final Date nowMinus1 = new Date(now.getTime() - 1000);
		assertThat("incorrect token string", tt.getToken(), is("foobar"));
		assertThat("incorrect ID class", tt.getId(), is(UUID.class));
		assertThat("creation date after now", tt.getCreationDate().before(now), is(true));
		assertThat("creation date > 1 sec before now", tt.getCreationDate().after(nowMinus1), 
				is(true));
		assertThat("incorrect expiration date", tt.getExpirationDate(),
				is(new Date(tt.getCreationDate().getTime() + 5)));
		
		final TemporaryToken tt2 = new TemporaryToken("whee", 1);
		assertThat("same uuid for different instances", tt.getId().equals(tt2.getId()), is(false));
		
		final TemporaryHashedToken ht = tt.getHashedToken();
		assertThat("incorrect token hash", ht.getTokenHash(),
				is("w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI="));
		assertThat("incorrect id", ht.getId(), is(tt.getId()));
		assertThat("incorrect creation date", ht.getCreationDate(), is(tt.getCreationDate()));
		assertThat("incorrect expiration date", ht.getExpirationDate(),
				is(tt.getExpirationDate()));
		
		failCreateTemporaryToken("foo", -1, "lifetime must be >= 0");
		failCreateTemporaryToken(null, 0, "Missing argument: token");
		failCreateTemporaryToken("", 0, "Missing argument: token");
		failCreateTemporaryToken("\n", 0, "Missing argument: token");
	}
	
	private void failCreateTemporaryToken(
			final String token,
			final long timeInMS,
			final String exception) {
		try {
			new TemporaryToken(token, timeInMS);
			fail("created bad temporary token");
		} catch (IllegalArgumentException e) {
			assertThat("correct exception message", e.getMessage(),
					is(exception));
		}
	}
	
}
