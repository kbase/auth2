package us.kbase.auth2.kbase;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.ini4j.Ini;
import org.productivity.java.syslog4j.SyslogIF;
import org.slf4j.LoggerFactory;

import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.Builder;
import us.kbase.auth2.lib.identity.IdentityProviderConfig.IdentityProviderConfigurationException;
import us.kbase.auth2.service.AuthStartupConfig;
import us.kbase.auth2.service.SLF4JAutoLogger;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;
import us.kbase.common.service.JsonServerSyslog;
import us.kbase.common.service.JsonServerSyslog.RpcInfo;
import us.kbase.common.service.JsonServerSyslog.SyslogOutput;

public class KBaseAuthConfig implements AuthStartupConfig {
	
	//TODO JAVADOC
	
	/** The property name where the config class will look in the environment and the system
	 * properties for the configuration file location. System properties take precedence.
	 */
	public static final String KB_DEPLOY_CFG = "KB_DEPLOYMENT_CONFIG";
	private static final String CFG_LOC ="authserv2";
	private static final String DEFAULT_LOG_NAME = "KBaseAuthService2";
	private static final String TEMP_KEY_CFG_FILE = "temp-key-config-file";
	
	private static final String KEY_LOG_NAME = "log-name";
	private static final String KEY_MONGO_HOST = "mongo-host";
	private static final String KEY_MONGO_DB = "mongo-db";
	private static final String KEY_MONGO_RETRY_WRITES = "mongo-retrywrites";
	private static final String KEY_MONGO_USER = "mongo-user";
	private static final String KEY_MONGO_PWD = "mongo-pwd";
	private static final String KEY_COOKIE_NAME = "token-cookie-name";
	private static final String KEY_ENVIRONMENT_HEADER = "environment-header";
	private static final String KEY_TEMPLATE_DIR = "template-dir";
	private static final String KEY_ID_PROV = "identity-providers";
	private static final String KEY_ID_PROV_ENVS = "identity-provider-envs";
	private static final String KEY_PREFIX_ID_PROVS = "identity-provider-";
	private static final String KEY_SUFFIX_ID_PROVS_FACTORY = "-factory";
	private static final String KEY_SUFFIX_ID_PROVS_LOGIN_URL = "-login-url";
	private static final String KEY_SUFFIX_ID_PROVS_API_URL = "-api-url";
	private static final String KEY_SUFFIX_ID_PROVS_CLIENT_ID = "-client-id";
	private static final String KEY_SUFFIX_ID_PROVS_CLIENT_SEC =
			"-client-secret";
	private static final String KEY_SUFFIX_ID_PROVS_LOGIN_REDIRECT =
			"-login-redirect-url";
	private static final String KEY_SUFFIX_ID_PROVS_LINK_REDIRECT =
			"-link-redirect-url";
	private static final String KEY_SUFFIX_ID_PROVS_ENV = "-env-";
	private static final String KEY_SUFFIX_ID_PROVS_CUSTOM = "-custom-";
	private static final String TRUE = "true";
	private static final String ENVIRONMENT_HEADER_PREFIX = "X-";
	private static final String KEY_TEST_MODE_ENABLED = "test-mode-enabled";
	
	private final SLF4JAutoLogger logger;
	private final String mongoHost;
	private final String mongoDB;
	private final boolean mongoRetryWrites;
	private final Optional<String> mongoUser;
	private final Optional<char[]> mongoPwd;
	private final String cookieName;
	private final String environmentHeader;
	private final Set<IdentityProviderConfig> providers;
	private final boolean isTestModeEnabled;
	private final Path templateDir;

	public KBaseAuthConfig() throws AuthConfigurationException {
		this(getConfigPathFromEnv(), false);
	}
	
	public KBaseAuthConfig(final Path filepath, final boolean nullLogger) 
			throws AuthConfigurationException {
		final Map<String, String> cfg = getConfig(filepath);
		final String logname = getString(KEY_LOG_NAME, cfg);
		logger = nullLogger ? new NullLogger() : buildLogger(logname); 
		try {
			isTestModeEnabled = TRUE.equals(getString(KEY_TEST_MODE_ENABLED, cfg));
			templateDir = Paths.get(getString(KEY_TEMPLATE_DIR, cfg, true));
			mongoHost = getString(KEY_MONGO_HOST, cfg, true);
			mongoDB = getString(KEY_MONGO_DB, cfg, true);
			mongoRetryWrites = TRUE.equals(getString(KEY_MONGO_RETRY_WRITES, cfg));
			mongoUser = Optional.ofNullable(getString(KEY_MONGO_USER, cfg));
			Optional<String> mongop = Optional.ofNullable(getString(KEY_MONGO_PWD, cfg));
			if (mongoUser.isPresent() ^ mongop.isPresent()) {
				mongop = null; //GC
				throw new AuthConfigurationException(String.format(
						"Must provide both %s and %s params in config file " +
						"%s section %s if MongoDB authentication is to be used",
						KEY_MONGO_USER, KEY_MONGO_PWD, cfg.get(TEMP_KEY_CFG_FILE), CFG_LOC));
			}
			mongoPwd = mongop.isPresent() ?
					Optional.of(mongop.get().toCharArray()) : Optional.empty();
			mongop = null; //GC
			cookieName = getString(KEY_COOKIE_NAME, cfg, true);
			environmentHeader = getEnvironmentHeader(cfg);
			providers = getProviders(cfg);
		} catch (AuthConfigurationException e) {
			if (!nullLogger) {
				LoggerFactory.getLogger(getClass()).error(
						"Configuration error", e);
			}
			throw e;
		}
	}
	
	private SLF4JAutoLogger buildLogger(final String logname) {
		// Warning - this code is tested manually. Ensure
		// logs are making it to stdout after changing
		// TODO LOGGING just remove JsonServerSyslog altogether
		//              and get rid of Syslog4j. Not sure how much work this'd be
		JsonServerSyslog.setStaticUseSyslog(false);
		final JsonServerSyslog jssl = new JsonServerSyslog(
				logname == null ? DEFAULT_LOG_NAME : logname,
				null,
				JsonServerSyslog.LOG_LEVEL_INFO,
				true
		);
		jssl.changeOutput(new SyslogOutput() {
			
			@Override
			public void logToSystem(
					final SyslogIF log,
					final int level,
					final String message) {
				System.out.println(String.format(
						"[Auth2] Lvl: %s Message: %s", level, message));
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
		return new JsonServerSysLogAutoLogger(jssl);
	}

	private static final String INVALID_CHARS_REGEX = "[^A-Z-]+";
	private static final Pattern INVALID_CHARS = Pattern.compile(INVALID_CHARS_REGEX);
	
	private String getEnvironmentHeader(final Map<String, String> cfg)
			throws AuthConfigurationException {
		final String eh = getString(KEY_ENVIRONMENT_HEADER, cfg, true);
		if (!eh.startsWith(ENVIRONMENT_HEADER_PREFIX)) {
			throw new AuthConfigurationException(String.format(
					"Parameter %s must start with %s in configuration file %s, section %s",
					KEY_ENVIRONMENT_HEADER, ENVIRONMENT_HEADER_PREFIX,
					cfg.get(TEMP_KEY_CFG_FILE), CFG_LOC));
		}
		final Matcher m = INVALID_CHARS.matcher(eh);
		if (m.find()) {
			throw new AuthConfigurationException(String.format(
					"Illegal character in %s %s in configuration file %s, section %s: %s",
					KEY_ENVIRONMENT_HEADER, eh, cfg.get(TEMP_KEY_CFG_FILE), CFG_LOC,
					m.group()));
		}
		return eh;
	}

	private Set<IdentityProviderConfig> getProviders(
			final Map<String, String> cfg)
			throws AuthConfigurationException {
		final String comsepProv = getString(KEY_ID_PROV, cfg);
		final Set<IdentityProviderConfig> ips = new HashSet<>();
		if (comsepProv == null) {
			return ips;
		}
		for (String p: comsepProv.split(",")) {
			p = p.trim();
			if (p.isEmpty()) {
				continue;
			}
			final String pre = KEY_PREFIX_ID_PROVS + p;
			final String factory = getString(pre + KEY_SUFFIX_ID_PROVS_FACTORY, cfg, true);
			final String cliid = getString(pre + KEY_SUFFIX_ID_PROVS_CLIENT_ID, cfg, true);
			final String clisec = getString(pre + KEY_SUFFIX_ID_PROVS_CLIENT_SEC, cfg, true);
			final URL login = getURL(pre + KEY_SUFFIX_ID_PROVS_LOGIN_URL, cfg);
			final URL api = getURL(pre + KEY_SUFFIX_ID_PROVS_API_URL, cfg);
			final URL loginRedirect = getURL(pre + KEY_SUFFIX_ID_PROVS_LOGIN_REDIRECT, cfg);
			final URL linkRedirect = getURL(pre + KEY_SUFFIX_ID_PROVS_LINK_REDIRECT, cfg);
			try {
				final Builder ipcfg = IdentityProviderConfig.getBuilder(
						factory, login, api, cliid, clisec, loginRedirect, linkRedirect);
				addCustom(ipcfg, pre + KEY_SUFFIX_ID_PROVS_CUSTOM, cfg);
				addEnvs(ipcfg, pre, cfg);
				ips.add(ipcfg.build());
			} catch (IdentityProviderConfigurationException e) {
				throw new AuthConfigurationException(String.format(
						"Error building configuration for provider %s in " +
						"section %s of config file %s: %s",
						p, CFG_LOC, cfg.get(TEMP_KEY_CFG_FILE), e.getMessage()), e);
			}
		}
		return Collections.unmodifiableSet(ips);
	}
	
	private void addEnvs(
			final Builder idProviderConfig,
			final String prefix,
			final Map<String, String> cfg)
			throws AuthConfigurationException, IdentityProviderConfigurationException {
		final String envs = getString(KEY_ID_PROV_ENVS, cfg);
		if (envs == null) {
			return;
		}
		for (String e: envs.split(",")) {
			e = e.trim();
			if (e.isEmpty()) {
				continue;
			}
			final String pre = prefix + KEY_SUFFIX_ID_PROVS_ENV + e;
			final URL loginRedirect = getURL(pre + KEY_SUFFIX_ID_PROVS_LOGIN_REDIRECT, cfg);
			final URL linkRedirect = getURL(pre + KEY_SUFFIX_ID_PROVS_LINK_REDIRECT, cfg);
			idProviderConfig.withEnvironment(e, loginRedirect, linkRedirect);
		}
	}

	private void addCustom(
			final Builder idProviderConfig,
			final String keyprefix,
			final Map<String, String> cfg)
			throws IdentityProviderConfigurationException {
		for (final String key: cfg.keySet()) {
			if (key.startsWith(keyprefix)) { // no way for a key to be null
				idProviderConfig.withCustomConfiguration(key.replace(keyprefix, ""), cfg.get(key));
			}
		}
	}

	private URL getURL(final String key, final Map<String, String> cfg)
			throws AuthConfigurationException {
		final String url = getString(key, cfg, true);
		try {
			return new URL(url);
		} catch (MalformedURLException e) {
			throw new AuthConfigurationException(String.format(
					"Value %s of parameter %s in section %s of config " +
					"file %s is not a valid URL",
					url, key, CFG_LOC, cfg.get(TEMP_KEY_CFG_FILE)));
		}
	}
	
	private static class NullLogger implements SLF4JAutoLogger {

		@Override
		public void setCallInfo(String method, String id, String ipAddress) {
			//  do nothing
		}
	}

	private static class JsonServerSysLogAutoLogger implements SLF4JAutoLogger {
		
		@SuppressWarnings("unused")
		private JsonServerSyslog logger; // keep a reference to avoid gc

		private JsonServerSysLogAutoLogger(final JsonServerSyslog logger) {
			super();
			this.logger = logger;
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
	
	// returns null if no string
	private String getString(
			final String paramName,
			final Map<String, String> config)
			throws AuthConfigurationException {
		return getString(paramName, config, false);
	}
	
	private String getString(
			final String paramName,
			final Map<String, String> config,
			final boolean except)
			throws AuthConfigurationException {
		final String s = config.get(paramName);
		if (s != null && !s.trim().isEmpty()) {
			return s.trim();
		} else if (except) {
			throw new AuthConfigurationException(String.format(
					"Required parameter %s not provided in configuration file %s, section %s",
					paramName, config.get(TEMP_KEY_CFG_FILE), CFG_LOC));
		} else {
			return null;
		}
	}

	private static Path getConfigPathFromEnv()
			throws AuthConfigurationException {
		final String file = System.getProperty(KB_DEPLOY_CFG) == null ?
				System.getenv(KB_DEPLOY_CFG) : System.getProperty(KB_DEPLOY_CFG);
		if (file == null || file.trim().isEmpty()) {
			throw new AuthConfigurationException(String.format(
					"Deployment configuration variable %s not in " +
							"environment or system properties", KB_DEPLOY_CFG));
		}
		return Paths.get(file);
	}
	
	private Map<String, String> getConfig(final Path file)
			throws AuthConfigurationException {
		final File deploy = file.normalize().toAbsolutePath().toFile();
		final Ini ini;
		try {
			ini = new Ini(deploy);
		} catch (IOException ioe) {
			throw new AuthConfigurationException(String.format(
					"Could not read configuration file %s: %s",
					deploy, ioe.getMessage()), ioe);
		}
		final Map<String, String> config = ini.get(CFG_LOC);
		if (config == null) {
			throw new AuthConfigurationException(String.format(
					"No section %s in config file %s", CFG_LOC, deploy));
		}
		config.put(TEMP_KEY_CFG_FILE, deploy.getAbsolutePath());
		return config;
	}
	
	@Override
	public SLF4JAutoLogger getLogger() {
		return logger;
	}

	@Override
	public Set<IdentityProviderConfig> getIdentityProviderConfigs() {
		return providers;
	}
	
	@Override
	public Set<String> getEnvironments() {
		if (providers.isEmpty()) {
			return Collections.emptySet();
		}
		return providers.iterator().next().getEnvironments();
	}

	@Override
	public String getMongoHost() {
		return mongoHost;
	}

	@Override
	public String getMongoDatabase() {
		return mongoDB;
	}

	@Override
	public boolean getMongoRetryWrites() {
		return mongoRetryWrites;
	}
	
	@Override
	public Optional<String> getMongoUser() {
		return mongoUser;
	}

	@Override
	public Optional<char[]> getMongoPwd() {
		return mongoPwd;
	}
	
	@Override
	public String getTokenCookieName() {
		return cookieName;
	}
	
	@Override
	public String getEnvironmentHeaderName() {
		return environmentHeader;
	}
	
	@Override
	public boolean isTestModeEnabled() {
		return isTestModeEnabled;
	}
	
	@Override
	public Path getPathToTemplateDirectory() {
		return templateDir;
	}
}
