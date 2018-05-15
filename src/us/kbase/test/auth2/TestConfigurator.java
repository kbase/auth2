package us.kbase.test.auth2;

import java.io.File;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.Set;

import org.productivity.java.syslog4j.SyslogIF;

import com.google.common.base.Optional;

import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.service.AuthStartupConfig;
import us.kbase.auth2.service.SLF4JAutoLogger;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.JsonServerSyslog.RpcInfo;
import us.kbase.common.service.JsonServerSyslog.SyslogOutput;

public class TestConfigurator implements AuthStartupConfig {
	
	private static String mongoHost = null;
	private static String mongoDatabase = null;
	
	public static void setConfig(final String mongoHost, final String mongoDatabase) {
		TestConfigurator.mongoHost = mongoHost;
		TestConfigurator.mongoDatabase = mongoDatabase;
	}

	private final SLF4JAutoLogger logger;
	
	private static class TestLogger implements SLF4JAutoLogger {

		// maintain reference to avoid GC
		private final JsonServerSyslog logger;
		
		public TestLogger() {
			logger = new JsonServerSyslog(
					"AuthTestLogger",
					//TODO KBASECOMMON allow null for the fake config prop arg
					"thisisafakekeythatshouldntexistihope",
					JsonServerSyslog.LOG_LEVEL_INFO, true);
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

		@Override
		public String getCallID() {
			return JsonServerSyslog.getCurrentRpcInfo().getId();
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
		return mongoHost == null ? System.getProperty("AUTH2_TEST_MONGOHOST") : mongoHost;
	}

	@Override
	public String getMongoDatabase() {
		return mongoDatabase == null ? System.getProperty("AUTH2_TEST_MONGODB") : mongoDatabase;
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
		return "some_cookie";
	}

	@Override
	public boolean isTestModeEnabled() {
		return true;
	}

}
