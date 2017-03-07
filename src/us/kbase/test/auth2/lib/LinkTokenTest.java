package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.LinkIdentities;
import us.kbase.auth2.lib.LinkToken;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.token.TemporaryToken;
import us.kbase.test.auth2.TestCommon;

public class LinkTokenTest {

	private final static RemoteIdentityWithLocalID REMOTE1 = new RemoteIdentityWithLocalID(
			UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715b9"),
			new RemoteIdentityID("foo", "bar"),
			new RemoteIdentityDetails("user", "full", "email"));
	
	private final static AuthUser AUTH_USER;
	static {
		try {
			AUTH_USER = new NewUser(new UserName("foo"), new EmailAddress("f@g.com"),
					new DisplayName("bar"), REMOTE1, Instant.now(), null);
		} catch (Exception e) {
			throw new RuntimeException("fix yer tests newb", e);
		}
	}
	
	@Test
	public void emptyConstructor() throws Exception {
		final LinkToken lt = new LinkToken();
		assertThat("incorrect isLinked()", lt.isLinked(), is(true));
		assertThat("incorrect token", lt.getTemporaryToken(), is((TemporaryToken) null));
		assertThat("incorrect ids", lt.getLinkIdentities(), is((LinkIdentities) null));
	}
	
	@Test
	public void tokenConstructor() throws Exception {
		final LinkIdentities linkids = new LinkIdentities(AUTH_USER, "foobar");
		final TemporaryToken tt = new TemporaryToken("foo", Instant.now(), 10000);
		final LinkToken lt = new LinkToken(tt, linkids);
		assertThat("incorrect isLinked()", lt.isLinked(), is(false));
		assertThat("incorrect token id", lt.getTemporaryToken().getId(), is(tt.getId()));
		assertThat("incorrect token id", lt.getTemporaryToken().getToken(), is("foo"));
		assertThat("incorrect token id", lt.getTemporaryToken().getCreationDate(),
				is(tt.getCreationDate()));
		assertThat("incorrect token id", lt.getTemporaryToken().getExpirationDate(),
				is(tt.getExpirationDate()));
		
		assertThat("incorrect provider", lt.getLinkIdentities().getProvider(), is("foobar"));
		
		//check the user is correct
		assertThat("incorrect username", lt.getLinkIdentities().getUser().getUserName(),
				is(new UserName("foo")));
		assertThat("incorrect email", lt.getLinkIdentities().getUser().getEmail(),
				is(new EmailAddress("f@g.com")));
		assertThat("incorrect displayname", lt.getLinkIdentities().getUser().getDisplayName(),
				is(new DisplayName("bar")));
		assertThat("incorrect user id number",
				lt.getLinkIdentities().getUser().getIdentities().size(), is(1));
		assertThat("incorrect user identity",
				lt.getLinkIdentities().getUser().getIdentities().iterator().next(), is(
				new RemoteIdentityWithLocalID(
						UUID.fromString("ec8a91d3-5923-4639-8d12-0891c56715b9"),
						new RemoteIdentityID("foo", "bar"),
						new RemoteIdentityDetails("user", "full", "email"))));
		assertThat("incorrect creation date", lt.getLinkIdentities().getUser().getCreated(),
				is(AUTH_USER.getCreated()));
		assertThat("incorrect login date", lt.getLinkIdentities().getUser().getLastLogin(),
				is(Optional.absent()));
	}
	
	@Test
	public void constructFail() throws Exception {
		failConstruct(null, new LinkIdentities(AUTH_USER, "foo"),
				new NullPointerException("token"));
		failConstruct(new TemporaryToken("foo", Instant.now(), 10000), null,
				new NullPointerException("linkIdentities"));
	}
	
	private void failConstruct(
			final TemporaryToken token,
			final LinkIdentities li,
			final Exception e)
			throws Exception {
		try {
			new LinkToken(token, li);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
