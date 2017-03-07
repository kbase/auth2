package us.kbase.test.auth2.lib.token;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.TemporaryHashedToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class TokenTest {

	@Test
	public void equalsHashedToken() throws Exception {
		EqualsVerifier.forClass(HashedToken.class).usingGetClass().verify();
	}
	
	@Test
	public void equalsIncomingToken() {
		EqualsVerifier.forClass(IncomingToken.class).usingGetClass().verify();
	}
	
	@Test
	public void equalsIncomingHashedToken() {
		EqualsVerifier.forClass(IncomingHashedToken.class).usingGetClass().verify();
	}
	
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
		Thread.sleep(1);
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
	
	@Test
	public void hashedToken() throws Exception {
		final UUID id = UUID.randomUUID();
		final HashedToken ht = new HashedToken(TokenType.LOGIN, null, id, "foobar",
				new UserName("whee"), new Date(1), new Date(5));
		assertThat("incorrect token type", ht.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", ht.getTokenName(), is((String) null));
		assertThat("incorrect token id", ht.getId(), is(id));
		assertThat("incorrect token hash", ht.getTokenHash(), is("foobar"));
		assertThat("incorrect user", ht.getUserName(), is(new UserName("whee")));
		assertThat("incorrect creation date", ht.getCreationDate(), is(new Date(1)));
		assertThat("incorrect expiration date", ht.getExpirationDate(), is(new Date(5)));
		
		// test with named token
		final UUID id2 = UUID.randomUUID();
		final HashedToken ht2 = new HashedToken(TokenType.EXTENDED_LIFETIME, "ugh", id2, "foobar2",
				new UserName("whee2"), new Date(27), new Date(42));
		assertThat("incorrect token type", ht2.getTokenType(), is(TokenType.EXTENDED_LIFETIME));
		assertThat("incorrect token name", ht2.getTokenName(), is("ugh"));
		assertThat("incorrect token id", ht2.getId(), is(id2));
		assertThat("incorrect token hash", ht2.getTokenHash(), is("foobar2"));
		assertThat("incorrect user", ht2.getUserName(), is(new UserName("whee2")));
		assertThat("incorrect creation date", ht2.getCreationDate(), is(new Date(27)));
		assertThat("incorrect expiration date", ht2.getExpirationDate(), is(new Date(42)));
		
		final UserName u = new UserName("u");
		final Date c = new Date(1);
		final Date e = new Date(2);
		failCreateHashedToken(null, "foo", id, "foo", u, c, e, new NullPointerException("type"));
		failCreateHashedToken(TokenType.LOGIN, "foo", null, "foo", u, c, e,
				new NullPointerException("id"));
		failCreateHashedToken(TokenType.LOGIN, "foo", id, null, u, c, e,
				new IllegalArgumentException("Missing argument: tokenHash"));
		failCreateHashedToken(TokenType.LOGIN, "foo", id, "", u, c, e,
				new IllegalArgumentException("Missing argument: tokenHash"));
		failCreateHashedToken(TokenType.LOGIN, "foo", id, " ", u, c, e,
				new IllegalArgumentException("Missing argument: tokenHash"));
		failCreateHashedToken(TokenType.LOGIN, "foo", id, "foo", null, c, e,
				new NullPointerException("userName"));
		failCreateHashedToken(TokenType.LOGIN, "foo", id, "foo", u, null, e,
				new NullPointerException("creationDate"));
		failCreateHashedToken(TokenType.LOGIN, "foo", id, "foo", u, c, null,
				new NullPointerException("expirationDate"));
		failCreateHashedToken(TokenType.LOGIN, "foo", id, "foo", u, e, c,
				new IllegalArgumentException("expirationDate must be > creationDate"));
	}
	
	private void failCreateHashedToken(
			final TokenType type,
			final String tokenName,
			final UUID id,
			final String tokenHash,
			final UserName userName,
			final Date creationDate,
			final Date expirationDate,
			final Exception exception) {
		try {
			new HashedToken(type, tokenName, id, tokenHash, userName, creationDate,
					expirationDate);
			fail("made bad hashed token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void hashingTokens() throws Exception {
		assertThat("incorrect hash", HashedToken.hash("whee"),
				is("bG4rDP2oAAfmk9UrWVYIPqaHcOExDQ7QLRlcsUETsoQ="));
		failHashToken(null);
		failHashToken("");
		failHashToken("   \n");
	}

	private void failHashToken(final String token) {
		try {
			HashedToken.hash(token);
			fail("hashed bad input");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Missing argument: token"));
		}
	}
	
	@Test
	public void newToken() throws Exception {
		final NewToken nt = new NewToken(TokenType.LOGIN, "baz", new UserName("foo"), 10);
		Thread.sleep(1);
		final Date now = new Date();
		final Date nowMinus1 = new Date(now.getTime() - 1000);
		assertThat("incorrect token type", nt.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", nt.getTokenName(), is((String) null));
		assertThat("incorrect token string", nt.getToken(), is("baz"));
		assertThat("incorrect ID class", nt.getId(), is(UUID.class));
		assertThat("incorrect user", nt.getUserName(), is(new UserName("foo")));
		assertThat("creation date after now", nt.getCreationDate().before(now), is(true));
		assertThat("creation date > 1 sec before now", nt.getCreationDate().after(nowMinus1), 
				is(true));
		assertThat("incorrect expiration date", nt.getExpirationDate(),
				is(new Date(nt.getCreationDate().getTime() + 10)));
		
		final HashedToken ht = nt.getHashedToken();
		assertThat("incorrect token type", ht.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", ht.getTokenName(), is((String) null));
		assertThat("incorrect token id", ht.getId(), is(nt.getId()));
		assertThat("incorrect token hash", ht.getTokenHash(),
				is("uqWglk0zIPvAxqkiFARTyFE+okq4/QV3A0gEqWckgJY="));
		assertThat("incorrect user", ht.getUserName(), is(new UserName("foo")));
		assertThat("incorrect creation date", ht.getCreationDate(), is(nt.getCreationDate()));
		assertThat("incorrect expiration date", ht.getExpirationDate(),
				is(nt.getExpirationDate()));
		
		// test with named token
		final NewToken nt2 = new NewToken(TokenType.EXTENDED_LIFETIME, "myname", "bar",
				new UserName("foo2"), 15);
		Thread.sleep(1);
		final Date now2 = new Date();
		final Date nowMinus1_2 = new Date(now.getTime() - 1000);
		assertThat("incorrect token type", nt2.getTokenType(), is(TokenType.EXTENDED_LIFETIME));
		assertThat("incorrect token name", nt2.getTokenName(), is("myname"));
		assertThat("incorrect token string", nt2.getToken(), is("bar"));
		assertThat("incorrect ID class", nt2.getId(), is(UUID.class));
		assertThat("incorrect user", nt2.getUserName(), is(new UserName("foo2")));
		assertThat("creation date after now", nt2.getCreationDate().before(now2), is(true));
		assertThat("creation date > 1 sec before now", nt2.getCreationDate().after(nowMinus1_2), 
				is(true));
		assertThat("incorrect expiration date", nt2.getExpirationDate(),
				is(new Date(nt2.getCreationDate().getTime() + 15)));
		
		final UserName u = new UserName("foo");
		failCreateNewToken(null, "foo", u, 0, new NullPointerException("type"));
		failCreateNewToken(TokenType.LOGIN, null, u, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(TokenType.LOGIN, "", u, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(TokenType.LOGIN, " \t", u, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(TokenType.LOGIN, "foo", null, 0, new NullPointerException("userName"));
		failCreateNewToken(TokenType.LOGIN, "foo", u, -1,
				new IllegalArgumentException("lifetime must be >= 0"));
		
		//test named token errors
		failCreateNewToken(null, "myname", "foo", u, 0, new NullPointerException("type"));
		failCreateNewToken(TokenType.LOGIN, null, "foo", u, 0,
				new IllegalArgumentException("Missing argument: tokenName"));
		failCreateNewToken(TokenType.LOGIN, "", "foo", u, 0,
				new IllegalArgumentException("Missing argument: tokenName"));
		failCreateNewToken(TokenType.LOGIN, " \n", "foo", u, 0,
				new IllegalArgumentException("Missing argument: tokenName"));
		failCreateNewToken(TokenType.LOGIN, "myname", null, u, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(TokenType.LOGIN, "myname", "", u, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(TokenType.LOGIN, "myname", " \t", u, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(TokenType.LOGIN, "myname", "foo", null, 0,
				new NullPointerException("userName"));
		failCreateNewToken(TokenType.LOGIN, "myname", "foo", u, -1,
				new IllegalArgumentException("lifetime must be >= 0"));
	}
	
	private void failCreateNewToken(
			final TokenType type,
			final String token,
			final UserName userName,
			final long lifetimeInMS,
			final Exception exception) {
		try {
			new NewToken(type, token, userName, lifetimeInMS);
			fail("created bad token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	private void failCreateNewToken(
			final TokenType type,
			final String tokenName,
			final String token,
			final UserName userName,
			final long lifetimeInMS,
			final Exception exception) {
		try {
			new NewToken(type, tokenName, token, userName, lifetimeInMS);
			fail("created bad token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void tokenSet() throws Exception {
		final UUID id1 = UUID.randomUUID();
		final HashedToken ht1 = new HashedToken(TokenType.LOGIN, null, id1, "h1",
				new UserName("u"), new Date(1), new Date(2));
		final UUID id2 = UUID.randomUUID();
		final HashedToken ht2 = new HashedToken(TokenType.EXTENDED_LIFETIME, "n2", id2, "h2",
				new UserName("u"), new Date(3), new Date(4));
		final UUID id3 = UUID.randomUUID();
		final HashedToken ht3 = new HashedToken(TokenType.EXTENDED_LIFETIME, "n3", id3, "h3",
				new UserName("u"), new Date(5), new Date(6));
		
		final Set<HashedToken> tokens = new HashSet<>(Arrays.asList(ht1, ht2, ht3));
		//test removing current token from incoming set
		final TokenSet ts = new TokenSet(ht1, tokens);
		tokens.clear(); // test makes copy of set rather than using same set
		assertThat("incorrect current token", ts.getCurrentToken(), is(ht1));
		assertThat("incorrect token set", ts.getTokens(),
				is(new HashSet<>(Arrays.asList(ht2, ht3))));
		try { // test immutable
			ts.getTokens().add(ht1);
			fail("not immutable");
		} catch (UnsupportedOperationException e) {}
		
		final TokenSet ts2 = new TokenSet(ht2, Collections.emptySet());
		assertThat("incorrect current token", ts2.getCurrentToken(), is(ht2));
		assertThat("incorrect token set", ts2.getTokens(), is(Collections.emptySet()));
		
		failCreateTokenSet(null, Collections.emptySet(), new NullPointerException("current"));
		failCreateTokenSet(ht1, null, new NullPointerException("tokens"));
		final HashedToken htnewuser = new HashedToken(TokenType.LOGIN, "foo", id1, "foo",
				new UserName("u2"), new Date(1), new Date(2));
		failCreateTokenSet(ht1, new HashSet<>(Arrays.asList(ht2, htnewuser, ht3)),
				new IllegalArgumentException("Mixing tokens from different users is not allowed"));
		failCreateTokenSet(ht1, new HashSet<>(Arrays.asList(ht2, null, ht3)),
				new NullPointerException("One of the tokens in the incoming set is null"));
		
	}
	
	private void failCreateTokenSet(
			final HashedToken current,
			final Set<HashedToken> tokens,
			final Exception exception) {
		try {
			new TokenSet(current, tokens);
			fail("created bad token set");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
}
