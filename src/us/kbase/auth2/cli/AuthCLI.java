package us.kbase.auth2.cli;

import java.nio.file.Paths;

import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.identity.GlobusIdentityProvider.GlobusIdentityProviderConfigurator;
import us.kbase.auth2.lib.identity.GoogleIdentityProvider.GoogleIdentityProviderConfigurator;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.service.AuthBuilder;
import us.kbase.auth2.service.AuthConfig;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;
import us.kbase.auth2.service.kbase.KBaseAuthConfig;

public class AuthCLI {
	
	//TODO TEST
	//TODO JAVADOC
	//TODO IMPORT import users

	private static String NAME = "manageauth";
	
	public static void main(String[] args) {
		quietLogger();
		
		final IdentityProviderFactory fac =
				IdentityProviderFactory.getInstance();
		fac.register(new GlobusIdentityProviderConfigurator());
		fac.register(new GoogleIdentityProviderConfigurator());
		
		final Args a = new Args();
		JCommander jc = new JCommander(a);
		jc.setProgramName(NAME);
		
		try {
			jc.parse(args);
		} catch (RuntimeException e) {
			error(e, a);
		}
		if (a.help) {
			jc.usage();
			System.exit(0);
		}
		final AuthConfig cfg;
		final Authentication auth;
		try {
			cfg = new KBaseAuthConfig(Paths.get(a.deploy), true);
			auth = new AuthBuilder(cfg).getAuth();
		} catch (AuthConfigurationException | StorageInitException e) {
			error(e, a);
			throw new RuntimeException(); // error() stops execution
		}
		if (a.setroot) {
			System.out.println("Enter the new root password:");
			final char[] pwd = System.console().readPassword();
			final Password p = new Password(pwd);
			try {
				auth.createRoot(p);
			} catch (AuthStorageException e) {
				error(e, a);
			}
			p.clear();
			System.exit(0);
		}
	}
	
	private static void quietLogger() {
		((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME))
				.setLevel(Level.OFF);
	}

	private static void error(
			final Throwable e,
			final Args a) {
		System.out.println("Error: " + e.getMessage());
		if (a.verbose) {
			e.printStackTrace();
		}
		System.exit(1);
	}

	private static class Args {
		@Parameter(names = {"-h", "--help"}, help = true,
				description = "Display help.")
		private boolean help;
		
		@Parameter(names = {"-v", "--verbose"},
				description = "Show error stacktraces.")
		private boolean verbose;
		
		@Parameter(names = {"-d", "--deploy"}, required = true,
				description = "Path to the auth deploy.cfg file.")
		private String deploy;
		
		@Parameter(names = {"-r", "--set-root-password"},
				description = "Set the root user password.")
		private boolean setroot;

		@Override
		public String toString() {
			StringBuilder builder = new StringBuilder();
			builder.append("Args [help=");
			builder.append(help);
			builder.append(", deploy=");
			builder.append(deploy);
			builder.append(", setroot=");
			builder.append(setroot);
			builder.append("]");
			return builder.toString();
		}
	}
}
