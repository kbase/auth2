package us.kbase.test.auth2.kbase;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static us.kbase.test.auth2.TestCommon.set;

import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import org.apache.commons.io.FileUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.common.base.Optional;

import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.service.SLF4JAutoLogger;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;
import us.kbase.test.auth2.TestCommon;


public class KBaseAuthConfigTest {
	
	private static Path TEMP_DIR = null;
	
	@BeforeClass
	public static void setup() throws Exception {
		TestCommon.stfuLoggers();
		TEMP_DIR = TestCommon.getTempDir()
				.resolve(KBaseAuthConfigTest.class.getSimpleName());
		Files.createDirectories(TEMP_DIR);
		
	}
	
	@AfterClass
	public static void teardown() throws Exception {
		final boolean deleteTempFiles = TestCommon.isDeleteTempFiles();
		if (TEMP_DIR != null && Files.exists(TEMP_DIR) && deleteTempFiles) {
			FileUtils.deleteQuietly(TEMP_DIR.toFile());
		}
	}
	
	private Path writeTempFile(final String... contents) throws Exception {
		final Path tf = Files.createTempFile(TEMP_DIR, "testcfg", ".tmp");
		Files.write(tf, Arrays.asList(contents));
		return tf;
	}
	
	private void testLogger(final SLF4JAutoLogger logger, final boolean nullLogger) {
		// too much of a pain to really test. Just test manually which is trivial.
		logger.setCallInfo("GET", "foo", "0.0.0.0");
		
		assertThat("incorrect ID", logger.getCallID(), is(nullLogger ? (String) null : "foo"));
	}

	@Test
	public void minimalConfigFromProp() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"environment-header=    X-FOO-BAR     ",
				"token-cookie-name=cookiename"
				);
		final KBaseAuthConfig cfg;
		try {
			System.setProperty(KBaseAuthConfig.KB_DEPLOY_CFG, cfgfile.toString());
			TestCommon.getenv().put(KBaseAuthConfig.KB_DEPLOY_CFG, "fakefile");
			cfg = new KBaseAuthConfig();
		} finally {
			System.clearProperty(KBaseAuthConfig.KB_DEPLOY_CFG);
			TestCommon.getenv().remove(KBaseAuthConfig.KB_DEPLOY_CFG);
		}
		
		assertThat("incorrect mongo host", cfg.getMongoHost(), is("localhost:50000"));
		assertThat("incorrect mongo db", cfg.getMongoDatabase(), is("mydb"));
		assertThat("incorrect mongo user", cfg.getMongoUser(), is(Optional.absent()));
		assertThat("incorrect mongo pwd", cfg.getMongoPwd(), is(Optional.absent()));
		assertThat("incorrect test mode", cfg.isTestModeEnabled(), is(false));
		assertThat("incorrect id providers", cfg.getIdentityProviderConfigs(), is(set()));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect template dir", cfg.getPathToTemplateDirectory(),
				is(Paths.get("somedir")));
		assertThat("incorrect cookie name", cfg.getTokenCookieName(), is("cookiename"));
		assertThat("incorrect env header", cfg.getEnvironmentHeaderName(), is("X-FOO-BAR"));
		testLogger(cfg.getLogger(), false);
	}
	
	@Test
	public void maximalConfigFromEnv() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"mongo-user= muser",
				"mongo-pwd =  mpwd",
				"test-mode-enabled= true",
				"log-name = logname", // this is annoying to test
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=    X-FOO-BAR     ",
				"identity-provider-envs =   env1  \t   ,    , env2    ",
				"identity-providers = prov1   \t   ,    \t , prov2   ",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com",
				"identity-provider-prov1-custom-foo = bar",
				"identity-provider-prov1-custom-bat = baz",
				"identity-provider-prov1-env-env1-login-redirect-url = https://lor1-1.com",
				"identity-provider-prov1-env-env1-link-redirect-url = https://lir1-1.com",
				"identity-provider-prov1-env-env2-login-redirect-url = https://lor1-2.com",
				"identity-provider-prov1-env-env2-link-redirect-url = https://lir1-2.com",
				
				"identity-provider-prov2-factory = facclass2",
				"identity-provider-prov2-login-url = https://login.prov2.com",
				"identity-provider-prov2-api-url  = https://api.prov2.com",
				"identity-provider-prov2-client-id = clientid2",
				"identity-provider-prov2-client-secret = secret2",
				"identity-provider-prov2-login-redirect-url = https://loginredirect2.com",
				"identity-provider-prov2-link-redirect-url = https://linkredirect2.com",
				"identity-provider-prov2-env-env1-login-redirect-url = https://lor2-1.com",
				"identity-provider-prov2-env-env1-link-redirect-url = https://lir2-1.com",
				"identity-provider-prov2-env-env2-login-redirect-url = https://lor2-2.com",
				"identity-provider-prov2-env-env2-link-redirect-url = https://lir2-2.com"
				);
		final KBaseAuthConfig cfg;
		try {
			TestCommon.getenv().put(KBaseAuthConfig.KB_DEPLOY_CFG, cfgfile.toString());
			cfg = new KBaseAuthConfig();
		} finally {
			TestCommon.getenv().remove(KBaseAuthConfig.KB_DEPLOY_CFG);
		}
		
		assertThat("incorrect mongo host", cfg.getMongoHost(), is("localhost:50000"));
		assertThat("incorrect mongo db", cfg.getMongoDatabase(), is("mydb"));
		assertThat("incorrect mongo user", cfg.getMongoUser(), is(Optional.of("muser")));
		assertThat("incorrect mongo pwd",
				Arrays.equals(cfg.getMongoPwd().get(), "mpwd".toCharArray()), is(true));
		assertThat("incorrect test mode", cfg.isTestModeEnabled(), is(true));
		assertThat("incorrect id providers", cfg.getIdentityProviderConfigs(), is(set(
				IdentityProviderConfig.getBuilder(
						"facclass",
						new URL("https://login.prov1.com"),
						new URL("https://api.prov1.com"),
						"clientid",
						"secret",
						new URL("https://loginredirect.com"),
						new URL("https://linkredirect.com"))
						.withCustomConfiguration("foo", "bar")
						.withCustomConfiguration("bat", "baz")
						.withEnvironment("env1",
								new URL("https://lor1-1.com"), new URL("https://lir1-1.com"))
						.withEnvironment("env2",
								new URL("https://lor1-2.com"), new URL("https://lir1-2.com"))
						.build(),
				IdentityProviderConfig.getBuilder(
						"facclass2",
						new URL("https://login.prov2.com"),
						new URL("https://api.prov2.com"),
						"clientid2",
						"secret2",
						new URL("https://loginredirect2.com"),
						new URL("https://linkredirect2.com"))
						.withEnvironment("env1",
								new URL("https://lor2-1.com"), new URL("https://lir2-1.com"))
						.withEnvironment("env2",
								new URL("https://lor2-2.com"), new URL("https://lir2-2.com"))
						.build()
				)));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set("env1", "env2")));
		assertThat("incorrect template dir", cfg.getPathToTemplateDirectory(),
				is(Paths.get("somedir")));
		assertThat("incorrect cookie name", cfg.getTokenCookieName(), is("cookiename"));
		assertThat("incorrect env header", cfg.getEnvironmentHeaderName(), is("X-FOO-BAR"));
		testLogger(cfg.getLogger(), false);
	}
	
	@Test
	public void constructFromVarFailNoVar() throws Exception {
		failConstruct(new AuthConfigurationException("Deployment configuration variable " +
				"KB_DEPLOYMENT_CONFIG not in environment or system properties"));
		try {
			TestCommon.getenv().put(KBaseAuthConfig.KB_DEPLOY_CFG, "   \t   ");
			failConstruct(new AuthConfigurationException("Deployment configuration variable " +
					"KB_DEPLOYMENT_CONFIG not in environment or system properties"));
		} finally {
			TestCommon.getenv().remove(KBaseAuthConfig.KB_DEPLOY_CFG);
		}
		
		// the rest of the errors are tested with the Path based constructor, since the no-arg
		// constructor just delegates to it
	}
	
	private void failConstruct(final Exception expected) {
		try {
			new KBaseAuthConfig();
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void minimalConfigFromFileNullLogger() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"test-mode-enabled = false",
				"token-cookie-name=cookiename",
				"environment-header=    X-FOO-BAR-BAZ     ",
				"identity-providers =      \t    "
				);
		final KBaseAuthConfig cfg = new KBaseAuthConfig(cfgfile, true);
		
		assertThat("incorrect mongo host", cfg.getMongoHost(), is("localhost:50000"));
		assertThat("incorrect mongo db", cfg.getMongoDatabase(), is("mydb"));
		assertThat("incorrect mongo user", cfg.getMongoUser(), is(Optional.absent()));
		assertThat("incorrect mongo pwd", cfg.getMongoPwd(), is(Optional.absent()));
		assertThat("incorrect test mode", cfg.isTestModeEnabled(), is(false));
		assertThat("incorrect id providers", cfg.getIdentityProviderConfigs(), is(set()));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect template dir", cfg.getPathToTemplateDirectory(),
				is(Paths.get("somedir")));
		assertThat("incorrect cookie name", cfg.getTokenCookieName(), is("cookiename"));
		assertThat("incorrect env header", cfg.getEnvironmentHeaderName(), is("X-FOO-BAR-BAZ"));
		testLogger(cfg.getLogger(), true);
	}
	
	@Test
	public void maximalConfigFromFileStdLogger() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"mongo-user= muser",
				"mongo-pwd =  mpwd",
				"test-mode-enabled= true",
				"log-name = logname", // this is annoying to test
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-provider-envs =        ",
				"identity-providers = prov1   \t   ,    \t , prov2   ",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com",
				"identity-provider-prov1-custom-foo = bar",
				"identity-provider-prov1-custom-bat = baz",
				
				"identity-provider-prov2-factory = facclass2",
				"identity-provider-prov2-login-url = https://login.prov2.com",
				"identity-provider-prov2-api-url  = https://api.prov2.com",
				"identity-provider-prov2-client-id = clientid2",
				"identity-provider-prov2-client-secret = secret2",
				"identity-provider-prov2-login-redirect-url = https://loginredirect2.com",
				"identity-provider-prov2-link-redirect-url = https://linkredirect2.com"
				);
		final KBaseAuthConfig cfg = new KBaseAuthConfig(cfgfile, false);
		
		assertThat("incorrect mongo host", cfg.getMongoHost(), is("localhost:50000"));
		assertThat("incorrect mongo db", cfg.getMongoDatabase(), is("mydb"));
		assertThat("incorrect mongo user", cfg.getMongoUser(), is(Optional.of("muser")));
		assertThat("incorrect mongo pwd",
				Arrays.equals(cfg.getMongoPwd().get(), "mpwd".toCharArray()), is(true));
		assertThat("incorrect test mode", cfg.isTestModeEnabled(), is(true));
		assertThat("incorrect id providers", cfg.getIdentityProviderConfigs(), is(set(
				IdentityProviderConfig.getBuilder(
						"facclass",
						new URL("https://login.prov1.com"),
						new URL("https://api.prov1.com"),
						"clientid",
						"secret",
						new URL("https://loginredirect.com"),
						new URL("https://linkredirect.com"))
						.withCustomConfiguration("foo", "bar")
						.withCustomConfiguration("bat", "baz")
						.build(),
				IdentityProviderConfig.getBuilder(
						"facclass2",
						new URL("https://login.prov2.com"),
						new URL("https://api.prov2.com"),
						"clientid2",
						"secret2",
						new URL("https://loginredirect2.com"),
						new URL("https://linkredirect2.com"))
						.build()
				)));
		assertThat("incorrect envs", cfg.getEnvironments(), is(set()));
		assertThat("incorrect template dir", cfg.getPathToTemplateDirectory(),
				is(Paths.get("somedir")));
		assertThat("incorrect cookie name", cfg.getTokenCookieName(), is("cookiename"));
		assertThat("incorrect env header", cfg.getEnvironmentHeaderName(), is("X-FOO-BAR"));
		testLogger(cfg.getLogger(), false);
	}
	
	@Test
	public void constructWithPathFailNoSuchFile() {
		final Path cfgfile = TEMP_DIR.resolve("fakefile");
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Could not read configuration file %s: %s (No such file or directory)",
				cfgfile, cfgfile)));
	}
	
	@Test
	public void constructWithPathFailNoSection() throws Exception {
		final Path cfgfile = writeTempFile("");
		failConstruct(cfgfile, new AuthConfigurationException(
				"No section authserv2 in config file " + cfgfile));
	}
	
	@Test
	public void constructWithPathFailBadIni() throws Exception {
		final Path cfgfile = writeTempFile(
				"foo",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"environment-header=X-FOO-BAR",
				"token-cookie-name=cookiename"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Could not read configuration file %s: parse error (at line: 1): foo",
				cfgfile)));
	}
	
	// we test a selection of key / null or whitespace combinations to cover all individual
	// keys, but we don't cover every possible combination
	
	@Test
	public void constructWithPathFailNullHost() throws Exception {
		// also logs here - just check manually
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"environment-header=X-FOO-BAR",
				"token-cookie-name=cookiename"
				);
		failConstruct(cfgfile, false, new AuthConfigurationException(String.format(
				"Required parameter mongo-host not provided in configuration file %s, " +
				"section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailWhitespaceDB() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     \t   ",
				"template-dir = somedir",
				"environment-header=X-FOO-BAR",
				"token-cookie-name=cookiename"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter mongo-db not provided in configuration file %s, " +
				"section authserv2", cfgfile)));
	}
	
	
	@Test
	public void constructWithPathFailNullTemplateDir() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     db   ",
				"environment-header=X-FOO-BAR",
				"token-cookie-name=cookiename"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter template-dir not provided in configuration file %s, " +
				"section authserv2", cfgfile)));
	}
	
	
	@Test
	public void constructWithPathFailWhitespaceCookieName() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     db   ",
				"template-dir = somedir",
				"environment-header=X-FOO-BAR",
				"token-cookie-name=     \t  "
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter token-cookie-name not provided in configuration file %s, " +
				"section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailWhitespaceEnvHeader() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     db   ",
				"template-dir = somedir",
				"environment-header=   \t     ",
				"token-cookie-name=nomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnom"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter environment-header not provided in configuration file %s, " +
				"section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailEnvHeaderBadPrefix() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     db   ",
				"template-dir = somedir",
				"environment-header=   Y-FOO-BAR",
				"token-cookie-name=nomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnom"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Parameter environment-header must start with X- in configuration file %s, " +
				"section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailEnvHeaderBadCharacter() throws Exception {
		for (final String test: Arrays.asList("X-FOO_BAR/_", "X-FO0-BAR/0", "X-FOo-BAR/o")) {
			final String[] headerChar = test.split("/");
			final Path cfgfile = writeTempFile(
					"[authserv2]",
					"mongo-host=  localhost:50000    ",
					"mongo-db   =     db   ",
					"template-dir = somedir",
					"environment-header=   " + headerChar[0],
					"token-cookie-name=nomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnomnom"
					);
			failConstruct(cfgfile, new AuthConfigurationException(String.format(
					"Illegal character in environment-header %s in configuration file " +
					"%s, section authserv2: %s", headerChar[0], cfgfile, headerChar[1])));
		}
	}
	
	@Test
	public void constructWithPathFailNullMongoUser() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     db   ",
				"mongo-pwd = mypwd",
				"template-dir = somedir",
				"environment-header=X-FOO-BAR",
				"token-cookie-name= coooooooooookieeeee  "
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Must provide both mongo-user and mongo-pwd params in config file %s " +
				"section authserv2 if MongoDB authentication is to be used", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailWhitespaceMongoPwd() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     db   ",
				"mongo-user = user",
				"mongo-pwd =  ",
				"template-dir = somedir",
				"environment-header=X-FOO-BAR",
				"token-cookie-name= coooooooooookieeeee  "
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Must provide both mongo-user and mongo-pwd params in config file %s " +
				"section authserv2 if MongoDB authentication is to be used", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailNullProviderFactory() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				//"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter identity-provider-prov1-factory not provided in " +
				"configuration file %s, section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailBadLoginURL() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = htps://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Value htps://login.prov1.com of parameter identity-provider-prov1-login-url " +
				"in section authserv2 of config file %s is not a valid URL", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailFailBadApiURI() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://ap^i.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Error building configuration for provider prov1 in section authserv2 of " +
				"config file %s: API URL https://ap^i.prov1.com for facclass identity provider " +
				"is not a valid URI: Illegal character in authority at index 8: " +
				"https://ap^i.prov1.com", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailNullClientID() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
//				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter identity-provider-prov1-client-id not provided in " +
				"configuration file %s, section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailWhitespaceClientSecret() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret =    \t   ",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter identity-provider-prov1-client-secret not provided in " +
				"configuration file %s, section authserv2", cfgfile)));
	}

	@Test
	public void constructWithPathFailNullLoginRedirectURL() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
//				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter identity-provider-prov1-login-redirect-url not provided in " +
				"configuration file %s, section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailWhitespaceLinkRedirectURL() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url =   \t   "
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter identity-provider-prov1-link-redirect-url not provided in " +
				"configuration file %s, section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailNullEnvLoginRedirectURL() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-envs=foo",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com",
				"identity-provider-prov1-env-foo-link-redirect-url=https://lir2.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Required parameter identity-provider-prov1-env-foo-login-redirect-url not " +
				"provided in configuration file %s, section authserv2", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailBadEnvLoginRedirectURL() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-envs=foo",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com",
				"identity-provider-prov1-env-foo-login-redirect-url=htps://lor2.com",
				"identity-provider-prov1-env-foo-link-redirect-url=https://lir2.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Value htps://lor2.com of parameter " +
				"identity-provider-prov1-env-foo-login-redirect-url in section authserv2 of " +
				"config file %s is not a valid URL", cfgfile)));
	}
	
	@Test
	public void constructWithPathFailBadEnvLinkRedirectURL() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"template-dir = somedir",
				"token-cookie-name=cookiename",
				"environment-header=X-FOO-BAR",
				"identity-providers = prov1",
				"identity-provider-envs=foo",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com",
				"identity-provider-prov1-env-foo-login-redirect-url=https://lor2.com",
				"identity-provider-prov1-env-foo-link-redirect-url=https://li^r2.com"
				);
		failConstruct(cfgfile, new AuthConfigurationException(String.format(
				"Error building configuration for provider prov1 in section authserv2 of " +
				"config file %s: Link redirect URL for environment foo https://li^r2.com " +
				"for facclass identity provider is not a valid URI: Illegal character in " +
				"authority at index 8: https://li^r2.com", cfgfile)));
	}
	
	private void failConstruct(final Path cfgfile, final Exception expected) {
		failConstruct(cfgfile, true, expected);
	}
		
	private void failConstruct(
			final Path cfgfile,
			final boolean nullLogger,
			final Exception expected) {
		try {
			new KBaseAuthConfig(cfgfile, nullLogger);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, expected);
		}
	}
	
	@Test
	public void immutable() throws Exception {
		final Path cfgfile = writeTempFile(
				"[authserv2]",
				"mongo-host=  localhost:50000    ",
				"mongo-db   =     mydb   ",
				"mongo-user= muser",
				"mongo-pwd =  mpwd",
				"test-mode-enabled= true",
				"log-name = logname", // this is annoying to test
				"template-dir = somedir",
				"environment-header=X-FOO-BAR",
				"token-cookie-name=cookiename",
				"identity-providers = prov1   \t   ,    \t    ",
				"identity-provider-prov1-factory = facclass",
				"identity-provider-prov1-login-url = https://login.prov1.com",
				"identity-provider-prov1-api-url  = https://api.prov1.com",
				"identity-provider-prov1-client-id = clientid",
				"identity-provider-prov1-client-secret = secret",
				"identity-provider-prov1-login-redirect-url = https://loginredirect.com",
				"identity-provider-prov1-link-redirect-url = https://linkredirect.com",
				"identity-provider-prov1-custom-foo = bar",
				"identity-provider-prov1-custom-bat = baz"
				);
		final KBaseAuthConfig cfg = new KBaseAuthConfig(cfgfile, false);
		
		try {
			cfg.getIdentityProviderConfigs().add(IdentityProviderConfig.getBuilder(
						"facclass2",
						new URL("https://login.prov2.com"),
						new URL("https://api.prov2.com"),
						"clientid2",
						"secret2",
						new URL("https://loginredirect2.com"),
						new URL("https://linkredirect2.com"))
						.build());
			fail("expected exception");
		} catch (UnsupportedOperationException e) {
			// test passes
		}
	}
}
