package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.inst;

import java.net.URI;
import java.util.UUID;

import org.junit.Test;

import nl.jqno.equalsverifier.EqualsVerifier;
import us.kbase.auth2.lib.OAuth2StartData;
import us.kbase.auth2.lib.TemporarySessionData;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.test.auth2.TestCommon;

public class OAuth2StartDataTest {
	
	@Test
	public void equals() throws Exception {
		EqualsVerifier.forClass(OAuth2StartData.class).usingGetClass().verify();
	}

	@Test
	public void construct() throws Exception {
		final UUID id = UUID.randomUUID();
		final TemporaryToken tt = new TemporaryToken(
				TemporarySessionData.create(id, inst(40000), inst(70000)).login("state"),
				"sometoken");
		final OAuth2StartData oa2sd = OAuth2StartData.build(
				new URI("https://loldemocracy.com"), tt, "somestatevariable");
		
		assertThat("incorrect uri", oa2sd.getRedirectURI(),
				is(new URI("https://loldemocracy.com")));
		assertThat("incorrect token", oa2sd.getTemporaryToken(), is(new TemporaryToken(
				TemporarySessionData.create(id, inst(40000), inst(70000)).login("otherstate"),
				"sometoken")));
		assertThat("incorrect state", oa2sd.getState(), is("somestatevariable"));
	}
	
	@Test
	public void constructFail() throws Exception {
		final TemporaryToken tt = new TemporaryToken(
				TemporarySessionData.create(UUID.randomUUID(), inst(40000), inst(70000))
						.login("state"),
				"sometoken");
		failConstruct(null, tt, new NullPointerException("redirectURI"));
		failConstruct(
				new URI("https://foo.com"), null, new NullPointerException("temporaryToken"));
	}
	
	private void failConstruct(
			final URI uri,
			final TemporaryToken tt,
			final Exception expected) {
		try {
			OAuth2StartData.build(
					uri, tt, "the state var should be removed from this class very soon");
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
}
