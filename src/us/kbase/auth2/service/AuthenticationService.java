package us.kbase.auth2.service;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.nio.file.Paths;

import org.glassfish.hk2.utilities.binding.AbstractBinder;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.glassfish.jersey.server.ResourceConfig;
import org.glassfish.jersey.server.mvc.mustache.MustacheMvcFeature;
import org.slf4j.LoggerFactory;

import com.mongodb.MongoClient;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.service.LoggingFilter;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;
import us.kbase.auth2.service.exceptions.ExceptionHandler;
import us.kbase.auth2.service.template.TemplateProcessor;
import us.kbase.auth2.service.template.mustache.MustacheProcessor;

//TODO WAIT accept json in text/plain and application/x-www-form-urlencoded or manually handle it

public class AuthenticationService extends ResourceConfig {
	
	//TODO TEST
	//TODO JAVADOC
	
	private static AuthStartupConfig cfg = null;
	private static MongoClient mc;
	@SuppressWarnings("unused")
	private final SLF4JAutoLogger logger; //keep a reference to prevent GC
	
	public static void setConfig(final AuthStartupConfig config) {
		nonNull(config, "config");
		cfg = config;
	}
	
	public AuthenticationService()
			throws StorageInitException, AuthConfigurationException {
		if (cfg == null) {
			throw new IllegalStateException("Call setConfig() before " +
					"starting the server ya daft numpty");
		}
		quietLogger();
		logger = cfg.getLogger();
		try {
			buildApp(cfg, AuthExternalConfig.DEFAULT);
		} catch (StorageInitException e) {
			LoggerFactory.getLogger(getClass()).error(
					"Failed to initialize storage engine: " + e.getMessage(),
					e);
			throw e;
		} catch (AuthConfigurationException e) {
			LoggerFactory.getLogger(getClass()).error(
					"Invalid configuration: " + e.getMessage(), e);
			throw e;
		}
	}

	private void quietLogger() {
		((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME))
				.setLevel(Level.INFO);
	}

	private void buildApp(
			final AuthStartupConfig c,
			final ExternalConfig defaultExternalConfig)
			throws StorageInitException, AuthConfigurationException {
		final AuthBuilder ab;
		synchronized(this) {
			if (mc == null) {
				ab = new AuthBuilder(c, defaultExternalConfig);
				mc = ab.getMongoClient();
			} else {
				ab = new AuthBuilder(c, defaultExternalConfig, mc);
			}
		}
		packages("us.kbase.auth2.service.api", "us.kbase.auth2.service.ui");
		register(JacksonFeature.class);
		register(MustacheMvcFeature.class);
		final String templatePath = "templates";
		property(MustacheMvcFeature.TEMPLATE_BASE_PATH, templatePath);
		register(LoggingFilter.class);
		register(ExceptionHandler.class);
		final Authentication auth = ab.getAuth();
		register(new AbstractBinder() {
			@Override
			protected void configure() {
				bind(auth).to(Authentication.class);
				bind(new MustacheProcessor(Paths.get(templatePath).toAbsolutePath()))
					.to(TemplateProcessor.class);
				bind(c.getLogger()).to(SLF4JAutoLogger.class);
				bind(new AuthAPIStaticConfig(c.getTokenCookieName()))
						.to(AuthAPIStaticConfig.class);
			}
		});
	}
	
	static void shutdown() {
		mc.close();
	}
}
