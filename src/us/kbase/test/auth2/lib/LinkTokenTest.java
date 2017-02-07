package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import org.junit.Test;

import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.token.TemporaryToken;

public class LinkTokenTest {

	@Test
	public void emptyConstructor() throws Exception {
		final LinkToken lt = new LinkToken();
		assertThat("incorrect isLinked()", lt.isLinked(), is(true));
		assertThat("incorrect token", lt.getTemporaryToken(), is((TemporaryToken) null));
	}
	
	@Test
	public void tokenConstructor() throws Exception {
		final TemporaryToken tt = new TemporaryToken("foo", 10000);
		final LinkToken lt = new LinkToken(tt);
		assertThat("incorrect isLinked()", lt.isLinked(), is(false));
		assertThat("incorrect token id", lt.getTemporaryToken().getId(), is(tt.getId()));
		assertThat("incorrect token id", lt.getTemporaryToken().getToken(), is("foo"));
		assertThat("incorrect token id", lt.getTemporaryToken().getCreationDate(),
				is(tt.getCreationDate()));
		assertThat("incorrect token id", lt.getTemporaryToken().getExpirationDate(),
				is(tt.getExpirationDate()));
	}
	
	@Test
	public void constructFail() throws Exception {
		try {
			new LinkToken(null);
			fail("constructed bad LinkToken");
		} catch (NullPointerException npe) {
			assertThat("inccorrect exception message", npe.getMessage(), is("token"));
		}
	}
	
}
