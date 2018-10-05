package us.kbase.test.auth2.service;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.client.Invocation.Builder;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.slf4j.LoggerFactory;

import com.google.common.base.Optional;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.AppenderBase;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthStartupConfig;
import us.kbase.auth2.service.LoggingFilter;
import us.kbase.auth2.service.SLF4JAutoLogger;
import us.kbase.common.test.RegexMatcher;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.StandaloneAuthServer;
import us.kbase.test.auth2.TestCommon;
import us.kbase.test.auth2.StandaloneAuthServer.ServerThread;

public class LoggingFilterTest {
	
	private static final String DB_NAME = "test_link_ui";
	private static final String COOKIE_NAME = "login-cookie";
	
	private static final Client CLI = ClientBuilder.newClient();
	
	private static MongoStorageTestManager manager = null;
	private static StandaloneAuthServer server = null;
	private static int port = -1;
	private static String host = null;
	
	private static List<ILoggingEvent> logEvents = new LinkedList<>();
	
	private static SLF4JAutoLogger autologgermock = mock(SLF4JAutoLogger.class);
	
	public static class LoggingFilterTestConfig implements AuthStartupConfig {
		
		public static String mongohost;

		@Override
		public SLF4JAutoLogger getLogger() {
			return autologgermock;
		}

		@Override
		public Set<IdentityProviderConfig> getIdentityProviderConfigs() {
			return set();
		}

		@Override
		public String getMongoHost() {
			return mongohost;
		}

		@Override
		public String getMongoDatabase() {
			return DB_NAME;
		}

		@Override
		public Optional<String> getMongoUser() {
			return Optional.absent();
		}

		@Override
		public Optional<char[]> getMongoPwd() {
			return Optional.absent();
		}

		@Override
		public String getTokenCookieName() {
			return COOKIE_NAME;
		}
		
		@Override
		public boolean isTestModeEnabled() {
			return false;
		}
		
		@Override
		public Path getPathToTemplateDirectory() {
			return Paths.get("templates");
		}

		@Override
		public Set<String> getEnvironments() {
			return Collections.emptySet();
		}
	}
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		manager = new MongoStorageTestManager(DB_NAME);
		LoggingFilterTestConfig.mongohost = "localhost:" + manager.mongo.getServerPort();
		server = new StandaloneAuthServer(LoggingFilterTestConfig.class.getName());
		new ServerThread(server).start();
		System.out.println("Main thread waiting for server to start up");
		while (server.getPort() == null) {
			Thread.sleep(1000);
		}
		port = server.getPort();
		host = "http://localhost:" + port;
		setUpSLF4JTestLoggerAppender();
	}
	
	private static void setUpSLF4JTestLoggerAppender() {
		// MongoStorageTestManager turns off the logger, so reenable here
		final Logger logger = (Logger) LoggerFactory
				.getLogger("us.kbase.auth2.service.LoggingFilter");
		logger.setLevel(ch.qos.logback.classic.Level.ALL);
		final Logger authRootLogger = (Logger) LoggerFactory.getLogger("us.kbase.auth2");
		authRootLogger.setLevel(Level.ALL);
		authRootLogger.setAdditive(false);
		final AppenderBase<ILoggingEvent> appender =
				new AppenderBase<ILoggingEvent>() {
			@Override
			protected void append(final ILoggingEvent event) {
				logEvents.add(event);
			}
		};
		appender.start();
		authRootLogger.addAppender(appender);
	}
	
	@AfterClass
	public static void afterClass() throws Exception {
		if (server != null) {
			server.stop();
		}
		if (manager != null) {
			manager.destroy();
		}
	}
	
	@Before
	public void beforeTest() throws Exception {
		ServiceTestUtils.resetServer(manager, host, COOKIE_NAME);
		logEvents.clear();
		reset(autologgermock); // bad practice but too expensive to restart server per test
		// should look into unit testing the logger again at some point, but difficult to find
		// good examples of how to test with @Context injections, and what I did see was absurdly
		// complex
		// not that this isn't absurdly complex, but I could get it working anyway
	}
	
	private class SetCallInfoAnswer implements Answer<Void> {
		
		private String recordedmethod;
		private String recordedid;
		private String recordedip;

		@Override
		public Void answer(final InvocationOnMock inv) throws Throwable {
			recordedmethod = inv.getArgument(0);
			recordedid = inv.getArgument(1);
			recordedip = inv.getArgument(2);
			return null;
		}
		
		public void check(final String method, final String ip) {
			assertThat("incorrect method", recordedmethod, is(method));
			assertThat("invalid call id", recordedid, RegexMatcher.matches("\\d{16}"));
			assertThat("incorrect ip address", recordedip, is(ip));
		}
	}
	
	@Test
	public void ignoreIPHeaders() throws Exception {
		
		final SetCallInfoAnswer ans = new SetCallInfoAnswer();
		doAnswer(ans).when(autologgermock).setCallInfo(
				any(String.class), any(String.class), any(String.class));
		
		final IncomingToken admintoken = ServiceTestUtils.getAdminToken(manager);
		ServiceTestUtils.ignoreIpHeaders(host, admintoken);
		
		logEvents.clear();

		final URI target = UriBuilder.fromUri(host).path("/customroles").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.cookie(COOKIE_NAME, admintoken.getToken())
				.header("user-agent", "a user agent")
				.header("x-forwarded-for", "127.0.0.2, 127.0.0.3")
				.header("x-real-ip", "127.0.0.4");
		final Response res = req.get();

		assertThat("incorrect status code", res.getStatus(), is(200));
		ans.check("GET", "127.0.0.1");
		
		checkInfoEvents(String.format("GET %s/customroles 200 a user agent", host));
	}
	
	private void checkInfoEvents(final String... messages) {
		assertThat("incorrect number of log events: " + logEvents, logEvents.size(),
				is(messages.length));
		final Iterator<ILoggingEvent> i = logEvents.iterator();
		for (final String msg: messages) {
			final ILoggingEvent got = i.next();
			assertThat("incorrect log level", got.getLevel(), is(Level.INFO));
			assertThat("incorrect caller", got.getLoggerName(), is(LoggingFilter.class.getName()));
			assertThat("incorrect message", got.getFormattedMessage(), is(msg));
		}
	}
	
	@Test
	public void withXForwardedFor() throws Exception {
		
		final SetCallInfoAnswer ans = new SetCallInfoAnswer();
		doAnswer(ans).when(autologgermock).setCallInfo(
				any(String.class), any(String.class), any(String.class));
		
		final URI target = UriBuilder.fromUri(host).path("/").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("user-agent", "an user agent")
				.header("x-forwarded-for", "127.0.0.2, 127.0.0.3");
		final Response res = req.get();

		assertThat("incorrect status code", res.getStatus(), is(200));
		ans.check("GET", "127.0.0.2");
		
		checkInfoEvents("X-Forwarded-For: 127.0.0.2, 127.0.0.3, Remote IP: 127.0.0.1",
				String.format("GET %s/ 200 an user agent", host));
	}
	
	@Test
	public void withXRealIP() throws Exception {
		
		final SetCallInfoAnswer ans = new SetCallInfoAnswer();
		doAnswer(ans).when(autologgermock).setCallInfo(
				any(String.class), any(String.class), any(String.class));
		
		final URI target = UriBuilder.fromUri(host).path("/").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("user-agent", "the user specific agent")
				.header("x-real-ip", "127.0.0.4");
		final Response res = req.get();

		assertThat("incorrect status code", res.getStatus(), is(200));
		ans.check("GET", "127.0.0.4");
		
		checkInfoEvents("X-Real-IP: 127.0.0.4, Remote IP: 127.0.0.1",
				String.format("GET %s/ 200 the user specific agent", host));
	}

	@Test
	public void withBothIPHeaders() throws Exception {
		
		final SetCallInfoAnswer ans = new SetCallInfoAnswer();
		doAnswer(ans).when(autologgermock).setCallInfo(
				any(String.class), any(String.class), any(String.class));
		
		final URI target = UriBuilder.fromUri(host).path("/").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("user-agent", "the user agent")
				.header("x-forwarded-for", "    127.0.0.2,     127.0.0.3    ")
				.header("x-real-ip", "   127.0.0.4    ");
		final Response res = req.get();

		assertThat("incorrect status code", res.getStatus(), is(200));
		ans.check("GET", "127.0.0.2");
		
		checkInfoEvents("X-Forwarded-For: 127.0.0.2,     127.0.0.3, " +
				"X-Real-IP: 127.0.0.4, Remote IP: 127.0.0.1",
				String.format("GET %s/ 200 the user agent", host));
	}
	
	@Test
	public void withNeitherIPHeader() throws Exception {
		
		final SetCallInfoAnswer ans = new SetCallInfoAnswer();
		doAnswer(ans).when(autologgermock).setCallInfo(
				any(String.class), any(String.class), any(String.class));
		
		final URI target = UriBuilder.fromUri(host).path("/").build();
		final WebTarget wt = CLI.target(target);
		final Builder req = wt.request()
				.header("user-agent", "always a user agent, never your user agent");
		final Response res = req.get();

		assertThat("incorrect status code", res.getStatus(), is(200));
		ans.check("GET", "127.0.0.1");
		
		checkInfoEvents(
				String.format("GET %s/ 200 always a user agent, never your user agent", host));
	}
}
