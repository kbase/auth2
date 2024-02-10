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
import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.test.auth2.TestCommon;

public class LinkTokenTest {

	@Test
	public void equals() {
		EqualsVerifier.forClass(LinkToken.class).usingGetClass().verify();
	}
	
	@Test
	public void emptyConstructor() throws Exception {
		final LinkToken lt = new LinkToken();
		assertThat("incorrect isLinked()", lt.isLinked(), is(true));
		assertThat("incorrect token", lt.getTemporaryToken(), is(Optional.empty()));
	}
	
	@Test
	public void tokenConstructor() throws Exception {
		final TemporaryToken tt = tempToken(
				UUID.randomUUID(), Instant.now(), 10000, "foo");
		final LinkToken lt = new LinkToken(tt);
		assertThat("incorrect isLinked()", lt.isLinked(), is(false));
		final TemporaryToken ttgot = lt.getTemporaryToken().get();
		assertThat("incorrect token id", ttgot.getId(), is(tt.getId()));
		assertThat("incorrect token id", ttgot.getToken(), is("foo"));
		assertThat("incorrect token id", ttgot.getCreationDate(),
				is(tt.getCreationDate()));
		assertThat("incorrect token id", ttgot.getExpirationDate(),
				is(tt.getExpirationDate()));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new NullPointerException("token"));
	}
	
	private void failConstruct(
			final TemporaryToken token,
			final Exception e)
			throws Exception {
		try {
			new LinkToken(token);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
