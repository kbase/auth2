package us.kbase.test.auth2.lib.token;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.TemporarySessionData;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.StoredToken.OptionalsStep;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenSet;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;

public class TokenTest {

	@Test
	public void equalsStoredToken() throws Exception {
		EqualsVerifier.forClass(StoredToken.class).usingGetClass().verify();
	}
	
	@Test
	public void equalsTemporaryToken() throws Exception {
		EqualsVerifier.forClass(TemporaryToken.class).usingGetClass().verify();
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
		failGetType(null, "Invalid token type: null");
		failGetType("foo", "Invalid token type: foo");
	}
	
	private void failGetType(final String type, final String exception) {
		try {
			TokenType.getType(type);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new IllegalArgumentException(exception));
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
		assertThat("incorrect toString()", it.toString(), is("IncomingToken [token=foo]"));
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
		final TemporarySessionData data = TemporarySessionData.create(id, i, 5)
				.link("state", new UserName("a"));
		final TemporaryToken tt = new TemporaryToken(data, "foobar");
		assertThat("incorrect token string", tt.getToken(), is("foobar"));
		assertThat("incorrect ID", tt.getId(), is(UUID.fromString(id.toString())));
		assertThat("incorrect creation date", tt.getCreationDate(),
				is(Instant.ofEpochMilli(4000)));
		assertThat("incorrect expiration date", tt.getExpirationDate(), is(i.plusMillis(5)));
		
		failCreateTemporaryToken(null, "foo", new NullPointerException("data"));
		failCreateTemporaryToken(data, null,
				new IllegalArgumentException("Missing argument: token"));
		failCreateTemporaryToken(data, "  \t \n  ",
				new IllegalArgumentException("Missing argument: token"));
	}
	
	private void failCreateTemporaryToken(
			final TemporarySessionData data,
			final String token,
			final Exception exception) {
		try {
			new TemporaryToken(data, token);
			fail("created bad temporary token");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, exception);
		}
	}
	
	@Test
	public void storedTokenMSLifetime() throws Exception {
		
		final UUID id = UUID.randomUUID();
		final StoredToken ht = StoredToken.getBuilder(TokenType.LOGIN, id, new UserName("whee"))
				.withLifeTime(Instant.ofEpochMilli(1000), 4000).build();
		assertThat("incorrect token type", ht.getTokenType(), is(TokenType.LOGIN));
		assertThat("incorrect token name", ht.getTokenName(), is(Optional.empty()));
		assertThat("incorrect token id", ht.getId(), is(id));
		assertThat("incorrect user", ht.getUserName(), is(new UserName("whee")));
		assertThat("incorrect creation date", ht.getCreationDate(),
				is(Instant.ofEpochMilli(1000)));
		assertThat("incorrect expiration date", ht.getExpirationDate(),
				is(Instant.ofEpochMilli(5000)));
		assertThat("incorrect context", ht.getContext(),
				is(TokenCreationContext.getBuilder().build()));
	}
	
	@Test
	public void storedTokenExpDateAndNameAndContext() throws Exception {
		final UUID id2 = UUID.randomUUID();
		final StoredToken ht2 = StoredToken.getBuilder(TokenType.DEV, id2, new UserName("whee2"))
				.withLifeTime(Instant.ofEpochMilli(27000), Instant.ofEpochMilli(42000))
				.withContext(TokenCreationContext.getBuilder().withNullableDevice("d").build())
				.withTokenName(new TokenName("ugh")).build();
		assertThat("incorrect token type", ht2.getTokenType(), is(TokenType.DEV));
		assertThat("incorrect token name", ht2.getTokenName(),
				is(Optional.of(new TokenName("ugh"))));
		assertThat("incorrect token id", ht2.getId(), is(id2));
		assertThat("incorrect user", ht2.getUserName(), is(new UserName("whee2")));
		assertThat("incorrect creation date", ht2.getCreationDate(),
				is(Instant.ofEpochMilli(27000)));
		assertThat("incorrect expiration date", ht2.getExpirationDate(),
				is(Instant.ofEpochMilli(42000)));
		assertThat("incorrect context", ht2.getContext(),
				is(TokenCreationContext.getBuilder().withNullableDevice("d").build()));
	}
	
	@Test
	public void storedTokenNullableName() throws Exception {
		final UUID id2 = UUID.randomUUID();
		final StoredToken ht2 = StoredToken.getBuilder(TokenType.DEV, id2, new UserName("whee2"))
				.withLifeTime(Instant.ofEpochMilli(27000), Instant.ofEpochMilli(42000))
				.withNullableTokenName(new TokenName("ugh")).build();
		assertThat("incorrect token type", ht2.getTokenType(), is(TokenType.DEV));
		assertThat("incorrect token name", ht2.getTokenName(),
				is(Optional.of(new TokenName("ugh"))));
		assertThat("incorrect token id", ht2.getId(), is(id2));
		assertThat("incorrect user", ht2.getUserName(), is(new UserName("whee2")));
		assertThat("incorrect creation date", ht2.getCreationDate(),
				is(Instant.ofEpochMilli(27000)));
		assertThat("incorrect expiration date", ht2.getExpirationDate(),
				is(Instant.ofEpochMilli(42000)));
		assertThat("incorrect context", ht2.getContext(),
				is(TokenCreationContext.getBuilder().build()));
	}
	
	@Test
	public void storedTokenEmptyNullableName() throws Exception {
		final UUID id2 = UUID.randomUUID();
		final StoredToken ht2 = StoredToken.getBuilder(TokenType.DEV, id2, new UserName("whee2"))
				.withLifeTime(Instant.ofEpochMilli(27000), Instant.ofEpochMilli(42000))
				.withNullableTokenName(null).build();
		assertThat("incorrect token type", ht2.getTokenType(), is(TokenType.DEV));
		assertThat("incorrect token name", ht2.getTokenName(), is(Optional.empty()));
		assertThat("incorrect token id", ht2.getId(), is(id2));
		assertThat("incorrect user", ht2.getUserName(), is(new UserName("whee2")));
		assertThat("incorrect creation date", ht2.getCreationDate(),
				is(Instant.ofEpochMilli(27000)));
		assertThat("incorrect expiration date", ht2.getExpirationDate(),
				is(Instant.ofEpochMilli(42000)));
		assertThat("incorrect context", ht2.getContext(),
				is(TokenCreationContext.getBuilder().build()));
	}
	
	@Test
	public void storedTokenSkipBuilderStep() throws Exception {
		final OptionalsStep st = ((OptionalsStep) StoredToken.getBuilder(
						TokenType.LOGIN, UUID.randomUUID(), new UserName("foo")));
		
		try {
			st.build();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("created"));
		}
	}
	
	@Test
	public void storedTokenCreateFail() throws Exception {
		final UUID id = UUID.randomUUID();
		final UserName u = new UserName("u");
		final Instant c = Instant.ofEpochMilli(1);
		final Instant e = Instant.ofEpochMilli(2);
		final TokenName tn = new TokenName("ugh");
		final TokenCreationContext ctx = TokenCreationContext.getBuilder().build();
		failCreateStoredToken(null, tn, id, u, c, e, ctx, new NullPointerException("type"));
		failCreateStoredToken(TokenType.LOGIN, null, id, u, c, e, ctx,
				new NullPointerException("tokenName"));
		failCreateStoredToken(TokenType.LOGIN, tn, null, u, c, e, ctx,
				new NullPointerException("id"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, null, c, e, ctx,
				new NullPointerException("userName"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, u, null, e, ctx,
				new NullPointerException("created"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, u, c, null, ctx,
				new NullPointerException("expires"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, u, e, c, ctx,
				new IllegalArgumentException("expires must be > created"));
		failCreateStoredToken(TokenType.LOGIN, tn, id, u, c, e, null,
				new NullPointerException("context"));
	}
	
	private void failCreateStoredToken(
			final TokenType type,
			final TokenName tokenName,
			final UUID id,
			final UserName userName,
			final Instant creationDate,
			final Instant expirationDate,
			final TokenCreationContext ctx,
			final Exception exception) {
		try {
			StoredToken.getBuilder(type, id, userName).withLifeTime(creationDate, expirationDate)
					.withTokenName(tokenName).withContext(ctx).build();
			fail("made bad hashed token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void hashingTokens() throws Exception {
		assertThat("incorrect hash", IncomingToken.hash("whee"),
				is("bG4rDP2oAAfmk9UrWVYIPqaHcOExDQ7QLRlcsUETsoQ="));
		assertThat("incorrect hash", IncomingToken.hash("wheex?xx>"),
				is("QO/Z+7OUGd3vNCsVujaaXee+iC8I8SwwehT+c8dDI68="));
		assertThat("incorrect hash", IncomingToken.hash("wheex?xx>", false),
				is("QO/Z+7OUGd3vNCsVujaaXee+iC8I8SwwehT+c8dDI68="));
		assertThat("incorrect hash", IncomingToken.hash("wheex?xx>", true),
				is("QO_Z-7OUGd3vNCsVujaaXee-iC8I8SwwehT-c8dDI68="));
		for (final String s: Arrays.asList(null, "", "   \n   ")) {
			failHashToken(s);
			failHashToken(s, true);
			failHashToken(s, false);
		}
	}

	private void failHashToken(final String token) {
		try {
			IncomingToken.hash(token);
			fail("hashed bad input");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Missing argument: token"));
		}
	}
	
	private void failHashToken(final String token, final boolean urlEncoding) {
		try {
			IncomingToken.hash(token, urlEncoding);
			fail("hashed bad input");
		} catch (IllegalArgumentException e) {
			assertThat("incorrect exception message", e.getMessage(),
					is("Missing argument: token"));
		}
	}
	
	@Test
	public void newToken() throws Exception {
		final UUID id = UUID.randomUUID();
		final StoredToken ht = StoredToken.getBuilder(TokenType.LOGIN, id, new UserName("whee"))
				.withLifeTime(Instant.ofEpochMilli(1000), 4000).build();
		
		final NewToken nt = new NewToken(ht, "baz");
		assertThat("incorrect stored token", nt.getStoredToken(), is(ht));
		assertThat("incorrect token string", nt.getToken(), is("baz"));
		assertThat("incorrect token hash", nt.getTokenHash(),
				is("uqWglk0zIPvAxqkiFARTyFE+okq4/QV3A0gEqWckgJY="));
		
		failCreateNewToken(null, "foo", new NullPointerException("storedToken"));
		failCreateNewToken(ht, null, new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(ht,  "", new IllegalArgumentException("Missing argument: token"));
		failCreateNewToken(ht, " \t", new IllegalArgumentException("Missing argument: token"));
	}
	
	private void failCreateNewToken(
			final StoredToken st,
			final String token,
			final Exception exception) {
		try {
			new NewToken(st,token);
			fail("created bad token");
		} catch (Exception e) {
			TestCommon.assertExceptionCorrect(e, exception);
		}
	}
	
	@Test
	public void tokenSet() throws Exception {
		final UUID id1 = UUID.randomUUID();
		final StoredToken ht1 = StoredToken.getBuilder(TokenType.LOGIN, id1, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(1000), 1000).build();
		final UUID id2 = UUID.randomUUID();
		final StoredToken ht2 = StoredToken.getBuilder(TokenType.DEV, id2, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(3000), 1000)
				.withTokenName(new TokenName("n2")).build();
		final UUID id3 = UUID.randomUUID();
		final StoredToken ht3 = StoredToken.getBuilder(TokenType.AGENT, id3, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(5000), 1000)
				.withTokenName(new TokenName("n3")).build();
		
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
		final StoredToken htnewuser = StoredToken.getBuilder(TokenType.LOGIN, id1,
					new UserName("u2"))
				.withLifeTime(Instant.ofEpochMilli(1000), 1000)
				.withTokenName(new TokenName("foo")).build();
		failCreateTokenSet(ht1, new HashSet<>(Arrays.asList(ht2, htnewuser, ht3)),
				new IllegalArgumentException("Mixing tokens from different users is not allowed"));
		failCreateTokenSet(ht1, new HashSet<>(Arrays.asList(ht2, null, ht3)),
				new NullPointerException("One of the tokens in the incoming set is null"));
		
	}
	
	@Test
	public void tokenSetIsSorted() throws Exception {
		final UUID id1 = UUID.fromString("edc1dcbb-d370-4660-a639-01a72f0d578a");
		final UUID id2 = UUID.fromString("8351a73a-d4c7-4c00-9a7d-012ace5d9519");
		final UUID id3 = UUID.fromString("653cc5ce-37e6-4e61-ac25-48831657f257");
		final UUID id4 = UUID.fromString("cb5e637c-cfbb-44eb-b179-843f3279f775");
		final UUID id5 = UUID.fromString("354c4f2d-a472-43aa-a4bd-84392b2d3407");
		
		final StoredToken ht1 = StoredToken.getBuilder(TokenType.LOGIN, id1, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(1000), 1000).build();
		final StoredToken ht2 = StoredToken.getBuilder(TokenType.DEV, id2, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(3000), 1000)
				.withTokenName(new TokenName("n2")).build();
		final StoredToken ht3 = StoredToken.getBuilder(TokenType.AGENT, id3, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(5000), 1000)
				.withTokenName(new TokenName("n3")).build();
		final StoredToken ht4 = StoredToken.getBuilder(TokenType.SERV, id4, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(7000), 1000)
				.withTokenName(new TokenName("n4")).build();
		final StoredToken ht5 = StoredToken.getBuilder(TokenType.SERV, id5, new UserName("u"))
				.withLifeTime(Instant.ofEpochMilli(8000), 1000)
				.withTokenName(new TokenName("n5")).build();

		// test that unmodifiable sets don't break anything
		final Set<StoredToken> tokens = Collections.unmodifiableSet(
						new HashSet<>(Arrays.asList(ht2, ht3, ht4, ht5)));
		final TokenSet ts = new TokenSet(ht1, tokens);
		final List<StoredToken> sorted = new LinkedList<>(ts.getTokens());
		assertThat("tokens not sorted", sorted, is(Arrays.asList(ht5, ht3, ht2, ht4)));
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
