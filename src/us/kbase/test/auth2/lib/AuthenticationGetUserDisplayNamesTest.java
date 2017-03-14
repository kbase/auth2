package us.kbase.test.auth2.lib;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.Test;

import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.InvalidTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationGetUserDisplayNamesTest {

	@Test
	public void getDisplayNamesSet() throws Exception {
		// includes test of removing root user
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final Map<UserName, DisplayName> expected = new HashMap<>();
		expected.put(new UserName("foo"), new DisplayName("dfoo"));
		expected.put(new UserName("bar"), new DisplayName("dbar"));

		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null, "foobarhash",
						new UserName("foo"), Instant.now(), Instant.now()));
		
		when(storage.getUserDisplayNames(
				set(new UserName("foo"), new UserName("bar"), new UserName("***ROOT***"))))
			.thenReturn(expected);
				
		
		final Map<UserName, DisplayName> disp = auth.getUserDisplayNames(
				token, set(new UserName("foo"), new UserName("bar"), new UserName("***ROOT***")));
		
		assertThat("incorrect display names", disp, is(expected));
	}
	
	@Test
	public void getDisplayNamesEmptySet() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null, "foobarhash",
						new UserName("foo"), Instant.now(), Instant.now()));
		
		final Map<UserName, DisplayName> disp = auth.getUserDisplayNames(
				token, Collections.emptySet());
		
		assertThat("incorrect display names", disp, is(new HashMap<>()));
	}
	
	@Test
	public void getDisplayNamesSetFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failGetDisplayNamesSet(auth, null, Collections.emptySet(),
				new NullPointerException("token"));
		failGetDisplayNamesSet(auth, new IncomingToken("token"), null,
				new NullPointerException("userNames"));
		failGetDisplayNamesSet(auth, new IncomingToken("token"), set(new UserName("foo"), null),
				new NullPointerException("Null name in userNames"));
	}
	
	@Test
	public void getDisplayNamesSetFailBadToken() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		when(storage.getToken(token.getHashedToken())).thenThrow(new NoSuchTokenException("foo"));
		
		failGetDisplayNamesSet(auth, token, Collections.emptySet(), new InvalidTokenException());
	}
	
	@Test
	public void getDisplayNamesSetFailTooManyUsers() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		
		final Set<UserName> users = new HashSet<>();
		for (int i = 0; i < 10001; i++) {
			users.add(new UserName("u" + i));
		}
		
		when(storage.getToken(token.getHashedToken()))
				.thenReturn(new HashedToken(UUID.randomUUID(), TokenType.LOGIN, null, "foobarhash",
						new UserName("foo"), Instant.now(), Instant.now()));
		
		failGetDisplayNamesSet(auth, token, users,
				new IllegalParameterException("User count exceeds maximum of 10000"));
	}
	
	private void failGetDisplayNamesSet(
			final Authentication auth,
			final IncomingToken token,
			final Set<UserName> names,
			final Exception e) {
		try {
			auth.getUserDisplayNames(token, names);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
	
}
