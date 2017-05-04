package us.kbase.test.auth2.service.api;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

import java.time.Instant;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.token.NewToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.service.api.APIToken;
import us.kbase.auth2.service.api.NewAPIToken;

public class APITokenTest {

	@Test
	public void apiTokenConstruct() throws Exception {
		final UUID id = UUID.randomUUID();
		final APIToken t = new APIToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 15000)
				.build(),
				20000L);
		
		assertThat("incorrect id", t.getId(), is(id.toString()));
		assertThat("incorrect cache time", t.getCachefor(), is(20000L));
	}
	
	
	@Test
	public void newApiTokenConstruct() throws Exception {
		final UUID id = UUID.randomUUID();
		final NewAPIToken t = new NewAPIToken(new NewToken(StoredToken.getBuilder(
				TokenType.AGENT, id, new UserName("foo"))
				.withLifeTime(Instant.ofEpochMilli(10000), 15000)
				.build(),
				"foobar"),
				20000L);
		
		assertThat("incorrect id", t.getId(), is(id.toString()));
		assertThat("incorrect cache time", t.getCachefor(), is(20000L));
		assertThat("incorrect token", t.getToken(), is("foobar"));
	}
	
}
