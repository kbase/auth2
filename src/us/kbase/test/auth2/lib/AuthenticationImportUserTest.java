package us.kbase.test.auth2.lib;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import static us.kbase.test.auth2.lib.AuthenticationTester.assertLogEventsCorrect;
import static us.kbase.test.auth2.lib.AuthenticationTester.initTestMocks;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.EmailAddress;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.user.NewUser;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.lib.AuthenticationTester.LogEvent;
import us.kbase.test.auth2.lib.AuthenticationTester.TestMocks;

public class AuthenticationImportUserTest {
	
	private static final RemoteIdentity REMOTE_ID = new RemoteIdentity(
			new RemoteIdentityID("prov", "id"),
			new RemoteIdentityDetails("user", "full", "e@g.com"));
	
	private static List<ILoggingEvent> logEvents;
	
	private static final UUID UID = UUID.randomUUID();
	
	@BeforeClass
	public static void beforeClass() {
		logEvents = AuthenticationTester.setUpSLF4JTestLoggerAppender();
	}
	
	@Before
	public void before() {
		logEvents.clear();
	}
	
	@Test
	public void importUser() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		when(testauth.randGenMock.randomUUID()).thenReturn(UID).thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.importUser(new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id"),
				new RemoteIdentityDetails("user", "full", "f@h.com")));
		
		verify(storage).createUser(
				NewUser.getBuilder(new UserName("foo"), UID, new DisplayName("full"),
						Instant.ofEpochMilli(10000),
						new RemoteIdentity(new RemoteIdentityID("prov", "id"),
								new RemoteIdentityDetails("user", "full", "f@h.com")))
						.withEmailAddress(new EmailAddress("f@h.com"))
						.build());
		
		assertLogEventsCorrect(logEvents, new LogEvent(Level.INFO,
				"Imported user foo", Authentication.class));
	}
	
	@Test
	public void importUserBadDisplayName() throws Exception {
		importUserBadDisplayName("full\nname");
		importUserBadDisplayName("     ");
	}

	private void importUserBadDisplayName(final String fullname) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		when(testauth.randGenMock.randomUUID()).thenReturn(UID).thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.importUser(new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id"),
				new RemoteIdentityDetails("user", fullname, "f@h.com")));
		
		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), UID,
				new DisplayName("unknown"), Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user", fullname, "f@h.com")))
				.withEmailAddress(new EmailAddress("f@h.com"))
				.build());
	}

	@Test
	public void importUserBadEmail() throws Exception {
		importUserBadEmail("email");
		importUserBadEmail("   \t ");
	}

	private void importUserBadEmail(final String email) throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		when(testauth.randGenMock.randomUUID()).thenReturn(UID).thenReturn(null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.importUser(new UserName("foo"), new RemoteIdentity(new RemoteIdentityID("prov", "id"),
				new RemoteIdentityDetails("user", "full", email)));
		
		verify(storage).createUser(NewUser.getBuilder(new UserName("foo"), UID,
				new DisplayName("full"), Instant.ofEpochMilli(10000),
				new RemoteIdentity(new RemoteIdentityID("prov", "id"),
						new RemoteIdentityDetails("user", "full", email)))
				.withEmailAddress(EmailAddress.UNKNOWN)
				.build());
	}
	
	@Test
	public void importUserFailNulls() throws Exception {
		final Authentication auth = initTestMocks().auth;
		
		failImportUser(auth, null, new RemoteIdentity(
				new RemoteIdentityID("prov", "id"),
				new RemoteIdentityDetails("user", "full", "email")),
				new NullPointerException("userName"));
		failImportUser(auth, new UserName("foo"), null,
				new NullPointerException("remoteIdentity"));
	}
	
	@Test
	public void importUserFailUserExists() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		when(testauth.randGenMock.randomUUID()).thenReturn(UID);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.importUser(new UserName("foo"), REMOTE_ID);
		
		doThrow(new UserExistsException("foo")).when(storage).createUser(
				NewUser.getBuilder(new UserName("foo"), UID, new DisplayName("full"),
						Instant.ofEpochMilli(10000), REMOTE_ID)
						.withEmailAddress(new EmailAddress("e@g.com"))
						.build());
		
		failImportUser(auth, new UserName("foo"), REMOTE_ID, new UserExistsException("foo"));
	}
	
	@Test
	public void importUserFailAlreadyLinked() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		when(testauth.randGenMock.randomUUID()).thenReturn(UUID.randomUUID(), UID, null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.importUser(new UserName("foo"), REMOTE_ID);
		
		doThrow(new IdentityLinkedException("linked")).when(storage).createUser(
				NewUser.getBuilder(new UserName("foo2"), UID, new DisplayName("full"),
						Instant.ofEpochMilli(10000), REMOTE_ID)
						.withEmailAddress(new EmailAddress("e@g.com"))
						.build());
		
		failImportUser(auth, new UserName("foo2"), REMOTE_ID,
				new IdentityLinkedException("linked"));
	}
	
	@Test
	public void importUserFailNoSuchRole() throws Exception {
		final TestMocks testauth = initTestMocks();
		final AuthStorage storage = testauth.storageMock;
		final Clock clock = testauth.clockMock;
		final Authentication auth = testauth.auth;
		
		when(testauth.randGenMock.randomUUID()).thenReturn(UUID.randomUUID(), UID, null);
		
		when(clock.instant()).thenReturn(Instant.ofEpochMilli(10000));
		
		auth.importUser(new UserName("foo2"), REMOTE_ID);
		
		doThrow(new NoSuchRoleException("foo")).when(storage).createUser(
				NewUser.getBuilder(new UserName("foo"), UID, new DisplayName("full"),
						Instant.ofEpochMilli(10000), REMOTE_ID)
						.withEmailAddress(new EmailAddress("e@g.com"))
						.build());
		
		failImportUser(auth, new UserName("foo"), REMOTE_ID,
				new RuntimeException("didn't supply any roles"));
	}

	private void failImportUser(
			final Authentication auth,
			final UserName userName,
			final RemoteIdentity remoteIdentity,
			final Exception e) {
		try {
			auth.importUser(userName, remoteIdentity);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}

}
