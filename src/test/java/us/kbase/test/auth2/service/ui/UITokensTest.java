package us.kbase.test.auth2.service.ui;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.TokenCreationContext;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.ui.NewUIToken;
import us.kbase.auth2.service.ui.UIToken;
import us.kbase.test.auth2.TestCommon;

public class UITokensTest {

	@Test
	public void constructUITokenMinimal() throws Exception {
		// only testing the methods in UIToken, not the supertype
		final UUID id = UUID.randomUUID();
		final UIToken t = new UIToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(30000))
				.build());
		
		assertThat("incorrect device", t.getDevice(), is((String) null));
		assertThat("incorrect agent", t.getAgent(), is((String) null));
		assertThat("incorrect agent version", t.getAgentver(), is((String) null));
		assertThat("incorrect os", t.getOs(), is((String) null));
		assertThat("incorrect os version", t.getOsver(), is((String) null));
		assertThat("incorrect ip", t.getIp(), is((String) null));
	}
	
	@Test
	public void constructUITokenMaximal() throws Exception {
		// only testing the methods in UIToken, not the supertype
		final UUID id = UUID.randomUUID();
		final UIToken t = new UIToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(30000))
				.withContext(TokenCreationContext.getBuilder()
						.withIpAddress(InetAddress.getByName("127.0.0.3"))
						.withNullableAgent("ag", "6")
						.withNullableDevice("dev")
						.withNullableOS("os1", "42")
						.build())
				.build());
		
		assertThat("incorrect device", t.getDevice(), is("dev"));
		assertThat("incorrect agent", t.getAgent(), is("ag"));
		assertThat("incorrect agent version", t.getAgentver(), is("6"));
		assertThat("incorrect os", t.getOs(), is("os1"));
		assertThat("incorrect os version", t.getOsver(), is("42"));
		assertThat("incorrect ip", t.getIp(), is("127.0.0.3"));
	}
	
	@Test
	public void constructUITokenFail() throws Exception {
		try {
			new UIToken(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("storedToken"));
		}
	}
	
	@Test
	public void constructNewUIToken() throws Exception {
		// only testing the methods in NewUIToken, not the supertype
		final UUID id = UUID.randomUUID();
		final NewUIToken t = new NewUIToken(new NewToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), Instant.ofEpochMilli(30000))
				.build(), "wheewhee"));
		
		assertThat("incorrect token", t.getToken(), is("wheewhee"));
		
	}
	
	@Test
	public void constructNewUITokenFail() throws Exception {
		try {
			new NewUIToken(null);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, new NullPointerException("token"));
		}
	}
	
}
