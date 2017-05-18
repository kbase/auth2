package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static us.kbase.test.auth2.TestCommon.set;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.PolicyID;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.lib.token.StoredToken;
import us.kbase.auth2.lib.token.TokenType;
import us.kbase.auth2.lib.user.AuthUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.AbstractAuthOperation;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationPolicyIDTest {
	
	/* Tests policy ID related functions that are not covered as part of other tests, e.g.
	 * login tests and get / create user tests.
	 */
	
	
	private static List<ILoggingEvent> logEvents;
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
	@Test
	public void removePolicyID() throws Exception {
		removePolicyID(new UserName("foo"), Role.ADMIN);
	}
	
	@Test
	public void removePolicyIDExecuteStandardUserCheckingTests() throws Exception {
		final IncomingToken token = new IncomingToken("foo");
		AuthenticationTester.executeStandardUserCheckingTests(new AbstractAuthOperation() {
			
			@Override
			public IncomingToken getIncomingToken() {
				return token;
			}
			
			@Override
			public void execute(final Authentication auth) throws Exception {
				auth.removePolicyID(token, new PolicyID("baz"));
			}

			@Override
			public List<ILoggingEvent> getLogAccumulator() {
				return logEvents;
			}
			
			@Override
			public String getOperationString() {
				return "remove policy ID baz";
			}
		}, set(Role.DEV_TOKEN, Role.SERV_TOKEN, Role.CREATE_ADMIN, Role.ROOT));
	}
	
	@Test
	public void removePolicyIDFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		failRemovePolicyID(auth, null, new PolicyID("foo"), new NullPointerException("token"));
		failRemovePolicyID(auth, new IncomingToken("foo"), null,
				new NullPointerException("policyID"));
	}
	

	private void removePolicyID(final UserName adminName, final Role adminRole) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Authentication auth = testauth.auth;
		
		final IncomingToken token = new IncomingToken("foobar");
		final StoredToken htoken = StoredToken.getBuilder(
				TokenType.LOGIN, UUID.randomUUID(), adminName)
				.withLifeTime(Instant.now(), Instant.now()).build();
		
		final AuthUser u = AuthUser.getBuilder(
				adminName, new DisplayName("foobar"), Instant.now())
				.withRole(adminRole).build();

		when(storage.getToken(token.getHashedToken())).thenReturn(htoken, (StoredToken) null);
		
		when(storage.getUser(adminName)).thenReturn(u, (AuthUser) null);
		
		auth.removePolicyID(token, new PolicyID("foo"));
		
		verify(storage).removePolicyID(new PolicyID("foo"));
	}
	
	private void failRemovePolicyID(
			final Authentication auth,
			final IncomingToken token,
			final PolicyID pid,
			final Exception e) {
		try {
			auth.removePolicyID(token, pid);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
