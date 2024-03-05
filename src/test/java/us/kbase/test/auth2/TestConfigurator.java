package us.kbase.test.auth2;

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;

import org.productivity.java.syslog4j.SyslogIF;

import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.service.AuthStartupConfig;
import us.kbase.auth2.service.SLF4JAutoLogger;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.JsonServerSyslog.RpcInfo;
import us.kbase.common.service.JsonServerSyslog.SyslogOutput;

public class TestConfigurator implements AuthStartupConfig {
	/* This is a test class for very specialized test applications and so does not contain
	 * a lot of documentation / safety checks / etc. It is expected that users are technically
	 * able to resolve problems that arise.
	 */
	
	public static final String MONGO_HOST_KEY = "AUTH2_TEST_MONGOHOST";
	public static final String MONGO_DB_KEY = "AUTH2_TEST_MONGODB";
	public static final String MONGO_TEMPLATES_KEY = "AUTH2_TEST_TEMPLATE_DIR";
	public static final String MONGO_USER_KEY = "AUTH2_TEST_MONGOUSER";
	public static final String MONGO_PWD_KEY = "AUTH2_TEST_MONGOPWD";
	
	private static String mongoHost = null;
	private static String mongoDatabase = null;
	private static String templatesDir = null;
	private static Optional<String> mongoUser = Optional.empty();
	private static Optional<char[]> mongoPwd = Optional.empty();
	
	public static void setConfig(
			final String mongoHost,
			final String mongoDatabase,
			final String templatesDir) {
		TestConfigurator.mongoHost = mongoHost;
		TestConfigurator.mongoDatabase = mongoDatabase;
		TestConfigurator.templatesDir = templatesDir;
		TestConfigurator.mongoUser = Optional.empty();
		TestConfigurator.mongoPwd = Optional.empty();
	}
	
	public static void setConfig(
			final String mongoHost,
			final String mongoDatabase,
			final String templatesDir,
			final String mongoUser,
			final char[] mongoPwd) {
		TestConfigurator.mongoHost = mongoHost;
		TestConfigurator.mongoDatabase = mongoDatabase;
		TestConfigurator.templatesDir = templatesDir;
		TestConfigurator.mongoUser = Optional.ofNullable(mongoUser);
		TestConfigurator.mongoPwd = Optional.ofNullable(mongoPwd);
	}

	private final SLF4JAutoLogger logger;
	
	private static class TestLogger implements SLF4JAutoLogger {

		// maintain reference to avoid GC
		private final JsonServerSyslog logger;
		
		public TestLogger() {
			JsonServerSyslog.setStaticUseSyslog(false);
			logger = new JsonServerSyslog(
					"AuthTestLogger",
					null,
					JsonServerSyslog.LOG_LEVEL_INFO,
					true
			);
			logger.changeOutput(new SyslogOutput() {
				
				@Override
				public void logToSystem(
						final SyslogIF log,
						final int level,
						final String message) {
					System.out.println(String.format(
							"[Syslog] Lvl: %s Message: %s", level, message));
				}
				
				@Override
				public PrintWriter logToFile(
						final File f,
						final PrintWriter pw,
						final int level,
						final String message) {
					System.out.println(
							"log to file called - this is not supported and not expected");
					return null;
				}
				
			});
		}
		
		@Override
		public void setCallInfo(
				final String method,
				final String id,
				final String ipAddress) {
			final RpcInfo rpc = JsonServerSyslog.getCurrentRpcInfo();
			rpc.setId(id);
			rpc.setIp(ipAddress);
			rpc.setMethod(method);
		}

	}
	
	public TestConfigurator() {
		logger = new TestLogger();
	}
	
	@Override
	public SLF4JAutoLogger getLogger() {
		return logger;
	}

	@Override
	public Set<IdentityProviderConfig> getIdentityProviderConfigs() {
		return Collections.emptySet();
	}

	@Override
	public String getMongoHost() {
		return mongoHost == null ? System.getProperty(MONGO_HOST_KEY) : mongoHost;
	}

	@Override
	public String getMongoDatabase() {
		return mongoDatabase == null ? System.getProperty(MONGO_DB_KEY) : mongoDatabase;
	}
	
	@Override
	public boolean getMongoRetryWrites() {
		return false;
	}

	@Override
	public Optional<String> getMongoUser() {
		return mongoUser.isPresent() ? mongoUser :
			Optional.ofNullable(System.getProperty(MONGO_USER_KEY));
	}

	@Override
	public Optional<char[]> getMongoPwd() {
		if (mongoPwd.isPresent()) {
			return mongoPwd;
		}
		final String mp = System.getProperty(MONGO_PWD_KEY);
		if (mp != null) {
			return Optional.of(mp.toCharArray());
		}
		return Optional.empty();
	}

	@Override
	public String getTokenCookieName() {
		return "some_cookie";
	}
	
	@Override
	public String getEnvironmentHeaderName() {
		return "X-SUPERFAKEHEADER";
	}

	@Override
	public boolean isTestModeEnabled() {
		return true;
	}
	
	@Override
	public Path getPathToTemplateDirectory() {
		return Paths.get(templatesDir == null ?
				System.getProperty(MONGO_TEMPLATES_KEY) : templatesDir);
	}

	@Override
	public Set<String> getEnvironments() {
		return Collections.emptySet();
	}

}
