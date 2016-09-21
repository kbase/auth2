package us.kbase.auth2.cli;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.NoSuchIdentityProviderException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.identity.GlobusIdentityProvider.GlobusIdentityProviderConfigurator;
import us.kbase.auth2.lib.identity.GoogleIdentityProvider.GoogleIdentityProviderConfigurator;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.lib.token.IncomingToken;
import us.kbase.auth2.service.AuthBuilder;
import us.kbase.auth2.service.AuthConfig;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;
import us.kbase.auth2.service.kbase.KBaseAuthConfig;

public class AuthCLI {
	
	//TODO TEST
	//TODO JAVADOC

	private static final String NAME = "manageauth";
	private static final String GLOBUS = "Globus";
	
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
		final Authentication auth;
		try {
			final AuthConfig cfg = new KBaseAuthConfig(
					Paths.get(a.deploy), true);
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
				p.clear(); //hardly necessary
				error(e, a);
			}
			p.clear(); //hardly necessary
			System.exit(0);
		}
		
		if (a.globus_users != null && !a.globus_users.trim().isEmpty()) {
			importUsers(a, auth);
		}
		
		jc.usage();
	}



	private static void importUsers(final Args a, final Authentication auth) {
		if (a.token == null || a.token.trim().isEmpty()) {
			System.out.println("Must supply a token in the -t parameter " +
					"if importing users");
			System.exit(1);
		}
		final Path p = Paths.get(a.globus_users);
		final List<String> users = getUserList(a, p);
		int success = 0;
		for (final String user: users) {
			if (user.isEmpty()) {
				continue;
			}
			System.out.println("Importing user " + user);
			try {
				auth.importUser(new IncomingToken(a.token), GLOBUS, user);
				success++;
			} catch (NoSuchIdentityProviderException e) {
				System.out.println(GLOBUS +
						" identity provider is not configured");
				System.exit(1);
			} catch (UserExistsException | IllegalParameterException |
					AuthStorageException | IdentityRetrievalException e) {
				error("\tError", e, a, true);
			}
		}
		System.out.println(String.format(
				"Imported %s out of %s users from file %s",
				success, users.size(), p));
		System.exit(0);
	}

	private static List<String> getUserList(final Args a, final Path p) {
		final String userstr;
		try {
			userstr = new String(Files.readAllBytes(p),
					StandardCharsets.UTF_8);
		} catch (NoSuchFileException e) {
			error("No such file", e, a);
			throw new RuntimeException(); //error() stops execution
		} catch (AccessDeniedException e) {
			error("Access denied", e, a);
			throw new RuntimeException(); //error() stops execution
		} catch (IOException e) {
			error(e, a);
			throw new RuntimeException(); //error() stops execution
		}
		final List<String> users = new ArrayList<>(new HashSet<>(
				Arrays.asList(userstr.split("[\\s,;]"))));
		users.sort(null);
		return users;
	}

	private static void quietLogger() {
		((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME))
				.setLevel(Level.OFF);
	}

	private static void error(final Throwable e, final Args a) {
		error("Error", e, a);
	}
	
	private static void error(
			final String msg,
			final Throwable e,
			final Args a) {
		error(msg, e, a, false);
	}
	
	private static void error(
			final String msg,
			final Throwable e,
			final Args a,
			final boolean continue_) {
		System.out.println(msg + ": " + e.getMessage());
		if (a.verbose) {
			e.printStackTrace();
		}
		if (!continue_) {
			System.exit(1);
		}
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
		
		@Parameter(names = {"-r", "--set-root-password"}, description =
				"Set the root user password. If this option is selected no " +
				"other specified operations will be executed.")
		private boolean setroot;
		
		@Parameter(names = {"-t", "--token"}, description =
				"A user token for use when importing users. Providing " +
				"a token without a users file does nothing.")
		private String token;
		
		@Parameter(names = {"--import-globus-users"}, description = 
				"A UTF-8 encoded file of whitespace, comma, or semicolon " +
				"separated Globus user names in the user@provider format " +
				"(for example. foo@globusid.org). A Globus token from " +
				"https://tokens.globus.org must be provided in the -t option.")
		private String globus_users;
	}
}
