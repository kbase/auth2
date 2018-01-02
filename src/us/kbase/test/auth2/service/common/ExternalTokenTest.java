package us.kbase.test.auth2.service.common;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import com.google.common.collect.ImmutableMap;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenName;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.common.ExternalToken;
import us.kbase.test.auth2.TestCommon;

public class ExternalTokenTest {
	
	@Test
	public void equals() {
		EqualsVerifier.forClass(ExternalToken.class).usingGetClass().verify();
	}
	
	@Test
	public void constructWithName() throws Exception {
		final UUID id = UUID.randomUUID();
		final ExternalToken et = new ExternalToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 15000)
				.withTokenName(new TokenName("bar"))
				.withContext(TokenCreationContext.getBuilder()
						.withCustomContext("whee", "whoo").build())
				.build());
		
		assertThat("incorrect type", et.getType(), is("Agent"));
		assertThat("incorrect id", et.getId(), is(id.toString()));
		assertThat("incorrect user", et.getUser(), is("foo"));
		assertThat("incorrect created", et.getCreated(), is(10000L));
		assertThat("incorrect expires", et.getExpires(), is(25000L));
		assertThat("incorrect name", et.getName(), is("bar"));
		assertThat("incorrect custom context", et.getCustom(),
				is(ImmutableMap.of("whee", "whoo")));
	}
	
	@Test
	public void constructWithoutName() throws Exception {
		final UUID id = UUID.randomUUID();
		final ExternalToken et = new ExternalToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 15000)
				.withContext(TokenCreationContext.getBuilder()
						.withCustomContext("whee", "whoo").build())
				.build());
		
		assertThat("incorrect type", et.getType(), is("Agent"));
		assertThat("incorrect id", et.getId(), is(id.toString()));
		assertThat("incorrect user", et.getUser(), is("foo"));
		assertThat("incorrect created", et.getCreated(), is(10000L));
		assertThat("incorrect expires", et.getExpires(), is(25000L));
		assertThat("incorrect name", et.getName(), is((String) null));
		assertThat("incorrect custom context", et.getCustom(),
				is(ImmutableMap.of("whee", "whoo")));
	}
	
	@Test
	public void constructFail() throws Exception {
		try {
			new ExternalToken(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("storedToken"));
		}
	}

}
