package us.kbase.test.auth2.lib.token;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.TokenName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TemporaryHashedToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class TokenTest {

	private static final Instant NOW = Instant.now();
	
	@Test
	public void equalsHashedToken() throws Exception {
		EqualsVerifier.forClass(HashedToken.class).usingGetClass().verify();
	}
	
	@Test
	public void equalsStoredToken() throws Exception {
		EqualsVerifier.forClass(StoredToken.class).usingGetClass().verify();
	}
	
	@Test
	public void equalsTemporaryToken() throws Exception {
		EqualsVerifier.forClass(TemporaryToken.class).usingGetClass().verify();
	}
	
	@Test
	public void equalsTemporaryHashedToken() throws Exception {
		EqualsVerifier.forClass(TemporaryHashedToken.class).usingGetClass().verify();
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
	public void equalsNewToken() {
		EqualsVerifier.forClass(NewToken.class).usingGetClass().verify();
	}
	
	@Test
	public void equalsTokenSet() {
		EqualsVerifier.forClass(TokenSet.class).usingGetClass().verify();
	}
	
	@Test
	public void tokenTypeGetType() throws Exception {
		assertThat("failed to get login token type", TokenType.getType("Login"),
				is(TokenType.LOGIN));
		assertThat("failed to get agent token type", TokenType.getType("Agent"),
				is(TokenType.AGENT));
		assertThat("failed to get developer token type", TokenType.getType("Dev"),
				is(TokenType.DEV));
		assertThat("failed to get service token type", TokenType.getType("Serv"),
				is(TokenType.SERV));
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
		assertThat("Incorrect id for agent token", TokenType.AGENT.getID(), is("Agent"));
		assertThat("Incorrect description for agent token", TokenType.AGENT.getDescription(),
				is("Agent"));
		assertThat("Incorrect id for dev token", TokenType.DEV.getID(), is("Dev"));
		assertThat("Incorrect description for dev token",
				TokenType.DEV.getDescription(), is("Developer"));
		assertThat("Incorrect id for serv token", TokenType.SERV.getID(), is("Serv"));
		assertThat("Incorrect description for serv token",
				TokenType.SERV.getDescription(), is("Service"));
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
		final Instant i = Instant.ofEpochMilli(4000);
		final UUID id = UUID.randomUUID();
		final TemporaryToken tt = new TemporaryToken(id, "foobar", i, 5L);
		assertThat("incorrect token string", tt.getToken(), is("foobar"));
		assertThat("incorrect ID", tt.getId(), is(UUID.fromString(id.toString())));
		assertThat("incorrect creation date", tt.getCreationDate(),
				is(Instant.ofEpochMilli(4000)));
		assertThat("incorrect expiration date", tt.getExpirationDate(), is(i.plusMillis(5)));
		
		final TemporaryHashedToken ht = tt.getHashedToken();
		assertThat("incorrect token hash", ht.getTokenHash(),
				is("w6uP8Tcg6K2QR905Rms8iXTlksL6OD1KOWBxTK7wxPI="));
		assertThat("incorrect id", ht.getId(), is(UUID.fromString(id.toString())));
		assertThat("incorrect creation date", ht.getCreationDate(),
				is(Instant.ofEpochMilli(4000)));
		assertThat("incorrect expiration date", ht.getExpirationDate(), is(i.plusMillis(5)));
		
		failCreateTemporaryToken(null, "foo", NOW, 0, new NullPointerException("id"));
		failCreateTemporaryToken(id, "foo", NOW, -1,
				new IllegalArgumentException("lifetime must be >= 0"));
		failCreateTemporaryToken(id, "foo", null, 0, new NullPointerException("creation"));
		failCreateTemporaryToken(id, null, NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateTemporaryToken(id, "", NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateTemporaryToken(id, "\n", NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
	}
	
	private void failCreateTemporaryToken(
			final UUID id,
			final String token,
			final Instant created,
			final long timeInMS,
			final Exception exception) {
		try {
			new TemporaryToken(id, token, created, timeInMS);
			fail("created bad temporary token");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, exception);
		}
	}
	
	@Test
	public void storedToken() throws Exception {
		
		final UUID id = UUID.randomUUID();
		final StoredToken ht = new StoredToken(id, TokenType.LOGIN, Optional.absent(),
				new UserName("whee"), Instant.ofEpochMilli(1000), Instant.ofEpochMilli(5000));
		assertThat("incorrect token type", ht.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", ht.getTokenName(), is(Optional.absent()));
		assertThat("incorrect token id", ht.getId(), is(id));
		assertThat("incorrect user", ht.getUserName(), is(new UserName("whee")));
		assertThat("incorrect creation date", ht.getCreationDate(),
				is(Instant.ofEpochMilli(1000)));
		assertThat("incorrect expiration date", ht.getExpirationDate(),
				is(Instant.ofEpochMilli(5000)));
		
		final StoredToken htnull = new StoredToken(id, TokenType.LOGIN, null,
				new UserName("whee"), Instant.ofEpochMilli(1000), Instant.ofEpochMilli(5000));
		assertThat("incorrect token name", htnull.getTokenName(), is(Optional.absent()));
		
		// test with named token
		final UUID id2 = UUID.randomUUID();
		final StoredToken ht2 = new StoredToken(id2,
				TokenType.DEV, Optional.of(new TokenName("ugh")),
				new UserName("whee2"), Instant.ofEpochMilli(27000), Instant.ofEpochMilli(42000));
		assertThat("incorrect token type", ht2.getTokenType(), is(TokenType.DEV));
		assertThat("incorrect token name", ht2.getTokenName(),
				is(Optional.of(new TokenName("ugh"))));
		assertThat("incorrect token id", ht2.getId(), is(id2));
		assertThat("incorrect user", ht2.getUserName(), is(new UserName("whee2")));
		assertThat("incorrect creation date", ht2.getCreationDate(),
				is(Instant.ofEpochMilli(27000)));
		assertThat("incorrect expiration date", ht2.getExpirationDate(),
				is(Instant.ofEpochMilli(42000)));
		
		final UserName u = new UserName("u");
		final Instant c = Instant.ofEpochMilli(1);
		final Instant e = Instant.ofEpochMilli(2);
		final Optional<TokenName> tn = Optional.of(new TokenName("ugh"));
		failCreateStoredToken(null, tn, id, u, c, e, new NullPointerException("type"));
		failCreateStoredToken(TokenType.LOGIN, tn, null, u, c, e,
				new NullPointerException("id"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, null, c, e,
				new NullPointerException("userName"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, u, null, e,
				new NullPointerException("creationDate"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, u, c, null,
				new NullPointerException("expirationDate"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, u, e, c,
				new IllegalArgumentException("expirationDate must be > creationDate"));
	}
	
	private void failCreateStoredToken(
			final TokenType type,
			final Optional<TokenName> tokenName,
			final UUID id,
			final UserName userName,
			final Instant creationDate,
			final Instant expirationDate,
			final Exception exception) {
		try {
			new StoredToken(id, type, tokenName, userName, creationDate, expirationDate);
			fail("made bad hashed token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void hashedToken() throws Exception {
		
		final UUID id = UUID.randomUUID();
		final HashedToken ht = new HashedToken(id, TokenType.LOGIN, Optional.absent(), "foobar",
				new UserName("whee"), Instant.ofEpochMilli(1000), Instant.ofEpochMilli(5000));
		assertThat("incorrect token type", ht.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", ht.getTokenName(), is(Optional.absent()));
		assertThat("incorrect token id", ht.getId(), is(id));
		assertThat("incorrect token hash", ht.getTokenHash(), is("foobar"));
		assertThat("incorrect user", ht.getUserName(), is(new UserName("whee")));
		assertThat("incorrect creation date", ht.getCreationDate(),
				is(Instant.ofEpochMilli(1000)));
		assertThat("incorrect expiration date", ht.getExpirationDate(),
				is(Instant.ofEpochMilli(5000)));
		
		final HashedToken htnull = new HashedToken(id, TokenType.LOGIN, null, "foobar",
				new UserName("whee"), Instant.ofEpochMilli(1000), Instant.ofEpochMilli(5000));
		assertThat("incorrect token name", htnull.getTokenName(), is(Optional.absent()));
		
		// test with named token
		final UUID id2 = UUID.randomUUID();
		final HashedToken ht2 = new HashedToken(id2,
				TokenType.DEV, Optional.of(new TokenName("ugh")), "foobar2",
				new UserName("whee2"), Instant.ofEpochMilli(27000), Instant.ofEpochMilli(42000));
		assertThat("incorrect token type", ht2.getTokenType(), is(TokenType.DEV));
		assertThat("incorrect token name", ht2.getTokenName(),
				is(Optional.of(new TokenName("ugh"))));
		assertThat("incorrect token id", ht2.getId(), is(id2));
		assertThat("incorrect token hash", ht2.getTokenHash(), is("foobar2"));
		assertThat("incorrect user", ht2.getUserName(), is(new UserName("whee2")));
		assertThat("incorrect creation date", ht2.getCreationDate(),
				is(Instant.ofEpochMilli(27000)));
		assertThat("incorrect expiration date", ht2.getExpirationDate(),
				is(Instant.ofEpochMilli(42000)));
		
		final UserName u = new UserName("u");
		final Instant c = Instant.ofEpochMilli(1);
		final Instant e = Instant.ofEpochMilli(2);
		final Optional<TokenName> tn = Optional.of(new TokenName("ugh"));
		failCreateHashedToken(null, tn, id, "foo", u, c, e, new NullPointerException("type"));
		failCreateHashedToken(TokenType.LOGIN, tn, null, "foo", u, c, e,
				new NullPointerException("id"));
		failCreateHashedToken(TokenType.LOGIN, tn, id, null, u, c, e,
				new IllegalArgumentException("Missing argument: tokenHash"));
		failCreateHashedToken(TokenType.LOGIN, tn, id, "", u, c, e,
				new IllegalArgumentException("Missing argument: tokenHash"));
		failCreateHashedToken(TokenType.LOGIN, tn, id, " ", u, c, e,
				new IllegalArgumentException("Missing argument: tokenHash"));
		failCreateHashedToken(TokenType.LOGIN, tn, id, "foo", null, c, e,
				new NullPointerException("userName"));
		failCreateHashedToken(TokenType.LOGIN, tn, id, "foo", u, null, e,
				new NullPointerException("creationDate"));
		failCreateHashedToken(TokenType.LOGIN, tn, id, "foo", u, c, null,
				new NullPointerException("expirationDate"));
		failCreateHashedToken(TokenType.LOGIN, tn, id, "foo", u, e, c,
				new IllegalArgumentException("expirationDate must be > creationDate"));
	}
	
	private void failCreateHashedToken(
			final TokenType type,
			final Optional<TokenName> tokenName,
			final UUID id,
			final String tokenHash,
			final UserName userName,
			final Instant creationDate,
			final Instant expirationDate,
			final Exception exception) {
		try {
			new HashedToken(id, type, tokenName, tokenHash, userName, creationDate,
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
		final Instant i = Instant.ofEpochMilli(60000);
		final UUID id = UUID.randomUUID();
		final NewToken nt = new NewToken(id, TokenType.LOGIN, "baz", new UserName("foo"), i, 10);
		assertThat("incorrect token type", nt.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", nt.getTokenName(), is(Optional.absent()));
		assertThat("incorrect token string", nt.getToken(), is("baz"));
		assertThat("incorrect ID", nt.getId(), is(UUID.fromString(id.toString())));
		assertThat("incorrect user", nt.getUserName(), is(new UserName("foo")));
		assertThat("incorrect creation date", nt.getCreationDate(), is(i));
		assertThat("incorrect expiration date", nt.getExpirationDate(), is(i.plusMillis(10)));
		
		final HashedToken ht = nt.getHashedToken();
		assertThat("incorrect token type", ht.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", ht.getTokenName(), is(Optional.absent()));
		assertThat("incorrect token id", ht.getId(), is(UUID.fromString(id.toString())));
		assertThat("incorrect token hash", ht.getTokenHash(),
				is("uqWglk0zIPvAxqkiFARTyFE+okq4/QV3A0gEqWckgJY="));
		assertThat("incorrect user", ht.getUserName(), is(new UserName("foo")));
		assertThat("incorrect creation date", ht.getCreationDate(),
				is(Instant.ofEpochMilli(60000)));
		assertThat("incorrect expiration date", ht.getExpirationDate(), is(i.plusMillis(10)));
		
		// test with named token
		final Instant i2 = Instant.ofEpochMilli(70000);
		final UUID id2 = UUID.randomUUID();
		final NewToken nt2 = new NewToken(id2, TokenType.SERV,
				new TokenName("myname"), "bar", new UserName("foo2"), i2, 15);
		assertThat("incorrect token type", nt2.getTokenType(), is(TokenType.SERV));
		assertThat("incorrect token name", nt2.getTokenName(),
				is(Optional.of(new TokenName("myname"))));
		assertThat("incorrect token string", nt2.getToken(), is("bar"));
		assertThat("incorrect ID", nt2.getId(), is(UUID.fromString(id2.toString())));
		assertThat("incorrect user", nt2.getUserName(), is(new UserName("foo2")));
		assertThat("incorrect creation date", nt2.getCreationDate(),
				is(Instant.ofEpochMilli(70000)));
		assertThat("incorrect expiration date", nt2.getExpirationDate(), is(i2.plusMillis(15)));
		
		final HashedToken ht2 = nt2.getHashedToken();
		assertThat("incorrect token type", ht2.getTokenType(), is(TokenType.SERV));
		assertThat("incorrect token name", ht2.getTokenName(),
				is(Optional.of(new TokenName("myname"))));
		assertThat("incorrect token string", ht2.getTokenHash(),
				is("/N4rLtula/QIYB+3If6bXDONEO5CnqBPrlURto+/j7k="));
		assertThat("incorrect ID", ht2.getId(), is(UUID.fromString(id2.toString())));
		assertThat("incorrect user", ht2.getUserName(), is(new UserName("foo2")));
		assertThat("incorrect creation date", ht2.getCreationDate(),
				is(Instant.ofEpochMilli(70000)));
		assertThat("incorrect expiration date", ht2.getExpirationDate(), is(i2.plusMillis(15)));
		
		final UserName u = new UserName("foo");
		failCreateNewToken(null, TokenType.LOGIN, "foo", u, NOW, 0,
				new NullPointerException("id"));
		failCreateNewToken(id, null, "foo", u, NOW, 0, new NullPointerException("type"));
		failCreateNewToken(id, TokenType.LOGIN, null, u, NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(id, TokenType.LOGIN, "", u, NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(id, TokenType.LOGIN, " \t", u, NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(id, TokenType.LOGIN, "foo", null, NOW, 0,
				new NullPointerException("userName"));
		failCreateNewToken(id, TokenType.LOGIN, "foo", u, null, 0,
				new NullPointerException("creation"));
		failCreateNewToken(id, TokenType.LOGIN, "foo", u, NOW, -1,
				new IllegalArgumentException("lifetime must be >= 0"));
		
		//test named token errors
		final TokenName tn = new TokenName("myname");
		failCreateNewToken(null, TokenType.LOGIN, tn, "foo", u, NOW, 0,
				new NullPointerException("id"));
		failCreateNewToken(id, null, tn, "foo", u, NOW, 0, new NullPointerException("type"));
		failCreateNewToken(id, TokenType.LOGIN, null, "foo", u, NOW, 0,
				new NullPointerException("tokenName"));
		failCreateNewToken(id, TokenType.LOGIN, tn, null, u, NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(id, TokenType.LOGIN, tn, "", u, NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(id, TokenType.LOGIN, tn, " \t", u, NOW, 0,
				new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(id, TokenType.LOGIN, tn, "foo", null, NOW, 0,
				new NullPointerException("userName"));
		failCreateNewToken(id, TokenType.LOGIN, tn, "foo", u, null, 0,
				new NullPointerException("creation"));
		failCreateNewToken(id, TokenType.LOGIN, tn, "foo", u, NOW, -1,
				new IllegalArgumentException("lifetime must be >= 0"));
	}
	
	private void failCreateNewToken(
			final UUID id,
			final TokenType type,
			final String token,
			final UserName userName,
			final Instant created,
			final long lifetimeInMS,
			final Exception exception) {
		try {
			new NewToken(id, type, token, userName, created, lifetimeInMS);
			fail("created bad token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	private void failCreateNewToken(
			final UUID id,
			final TokenType type,
			final TokenName tokenName,
			final String token,
			final UserName userName,
			final Instant created,
			final long lifetimeInMS,
			final Exception exception) {
		try {
			new NewToken(id, type, tokenName, token, userName, created, lifetimeInMS);
			fail("created bad token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void tokenSet() throws Exception {
		final UUID id1 = UUID.randomUUID();
		final StoredToken ht1 = new StoredToken(id1, TokenType.LOGIN, Optional.absent(),
				new UserName("u"), Instant.ofEpochMilli(1000), Instant.ofEpochMilli(2000));
		final UUID id2 = UUID.randomUUID();
		final StoredToken ht2 = new StoredToken(id2,
				TokenType.DEV, Optional.of(new TokenName("n2")),
				new UserName("u"), Instant.ofEpochMilli(3000), Instant.ofEpochMilli(4000));
		final UUID id3 = UUID.randomUUID();
		final StoredToken ht3 = new StoredToken(id3,
				TokenType.AGENT, Optional.of(new TokenName("n3")),
				new UserName("u"), Instant.ofEpochMilli(5000), Instant.ofEpochMilli(6000));
		
		final Set<StoredToken> tokens = new HashSet<>(Arrays.asList(ht1, ht2, ht3));
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
		final StoredToken htnewuser = new StoredToken(id1,
				TokenType.LOGIN, Optional.of(new TokenName("foo")),
				new UserName("u2"), Instant.ofEpochMilli(1000), Instant.ofEpochMilli(2000));
		failCreateTokenSet(ht1, new HashSet<>(Arrays.asList(ht2, htnewuser, ht3)),
				new IllegalArgumentException("Mixing tokens from different users is not allowed"));
		failCreateTokenSet(ht1, new HashSet<>(Arrays.asList(ht2, null, ht3)),
				new NullPointerException("One of the tokens in the incoming set is null"));
		
	}
	
	private void failCreateTokenSet(
			final StoredToken current,
			final Set<StoredToken> tokens,
			final Exception exception) {
		try {
			new TokenSet(current, tokens);
			fail("created bad token set");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
}
