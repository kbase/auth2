package us.kbase.auth2.cli;

import static java.util.Objects.requireNonNull;
import static us.kbase.auth2.Version.VERSION;

import java.io.Console;
import java.io.PrintStream;
import java.nio.file.Paths;

import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.github.zafarkhaja.semver.Version;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.storage.AuthStorage;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.service.AuthBuilder;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthStartupConfig;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;

/** The Client Line Interface for the authentication instance. Used for bootstrapping the instance.
 * @author gaprice@lbl.gov
 *
 */
public class AuthCLI {
	
	private static final String NAME = "manage_auth";
	
	/** Runs the CLI.
	 * @param args the program arguments.
	 */
	public static void main(String[] args) {
		// these lines are only tested manually, so don't make changes without testing manually.
		System.exit(new AuthCLI(args, new ConsoleWrapper(), System.out, System.err).execute());
	}
	
	// this is also only tested manually. Don't change without testing manually.
	/** A trivial wrapper for a {@link java.io.Console}. Can't mock it since it's a final class.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class ConsoleWrapper {
		
		private final Console console;
		
		public ConsoleWrapper() {
			// console will be null if output is redirected to a file
			console = System.console();
		}
		
		/** Read a password from the console with echoing disabled.
		 * @return the password, not including line termination characters. Null if EOL.
		 * @throws IllegalStateException if no console is available.
		 */
		public char[] readPassword() {
			if (console == null) {
				throw new IllegalStateException("Cannot read password from null console");
			}
			return console.readPassword();
		}
		
		/** Returns whether a console is available.
		 * @return true if a console is available.
		 */
		public boolean hasConsole() {
			return console != null;
		}
		
	}
	
	private final String[] args;
	private final ConsoleWrapper console;
	private final PrintStream out;
	private final PrintStream err;
	
	/** Create a new CLI instance.
	 * @param args the program arguments.
	 * @param console the system console.
	 * @param out the out printstream.
	 * @param err the error printstream.
	 */
	public AuthCLI(
			final String[] args,
			final ConsoleWrapper console,
			final PrintStream out,
			final PrintStream err) {
		requireNonNull(args, "args");
		requireNonNull(console, "console");
		requireNonNull(out, "out");
		requireNonNull(err, "err");
		this.args = args;
		this.console = console;
		this.out = out;
		this.err = err;
		quietLogger();
	}
		
	/** Execute the CLI command.
	 * @return the exit code.
	 */
	public int execute() {
		final Args a = new Args();
		JCommander jc = new JCommander(a);
		jc.setProgramName(NAME);

		try {
			jc.parse(args);
		} catch (ParameterException e) {
			printError(e, a);
			return 1;
		}
		if (a.help) {
			usage(jc);
			return 0;
		}
		final Authentication auth;
		final AuthStartupConfig cfg;
		final AuthStorage storage;
		try {
			// may need to be smarter here about figuring out the config implementation
			cfg = new KBaseAuthConfig(Paths.get(a.deploy), true);
			final AuthBuilder ab = new AuthBuilder(
					cfg, AuthExternalConfig.getDefaultConfig(cfg.getEnvironments()));
			auth = ab.getAuth();
			storage = ab.getStorage();
		} catch (AuthConfigurationException | StorageInitException e) {
			printError(e, a);
			return 1;
		}
		boolean usage = true;
		if (a.setroot) {
			final int ret = setRootPassword(a, auth);
			if (ret != 0) {
				return ret;
			};
			usage = false;
		}
		if (a.removeRecanonicalizationFlag) {
			try {
				final long count = storage.removeDisplayNameRecanonicalizationFlag(
						Version.valueOf(VERSION));
				out.println(String.format("Removed %s recanonicalization flags for version %s",
						count, VERSION));
			} catch (AuthStorageException e) { // this can't be tested easily
				printError(e, a);
				return 1;
			}
			usage = false;
		}
		if (a.recanonicalizeDisplayNames) {
			try {
				final long count = storage.recanonicalizeDisplayNames(Version.valueOf(VERSION));
				out.println(String.format("Recanonicalized %s user display names", count));
			} catch (AuthStorageException e) { // this can't be tested easily
				printError(e, a);
				return 1;
			}
			usage = false;
		}
		if (usage) {
			usage(jc);
		}
		return 0;
	}

	private int setRootPassword(final Args a, final Authentication auth) {
		int ret = 0;
		if (!console.hasConsole()) {
			err.println("No console available for entering password. Aborting.");
			ret = 1;
		} else {
			out.println("Enter the new root password:");
			final char[] pwd = console.readPassword();
			if (pwd == null || pwd.length == 0) {
				err.println("No password provided");
				ret = 1;
			} else {
				final Password p = new Password(pwd);
				Password.clearPasswordArray(pwd);
				try {
					auth.createRoot(p);
				} catch (AuthStorageException | IllegalPasswordException e) {
					printError(e, a);
					ret = 1;
				} finally {
					p.clear(); //hardly necessary
				}
			}
		}
		return ret;
	}

	private void usage(final JCommander jc) {
		final StringBuilder sb = new StringBuilder();
		jc.usage(sb);
		out.println(sb.toString());
	}

	private void quietLogger() {
		((Logger) LoggerFactory.getLogger(Logger.ROOT_LOGGER_NAME))
				.setLevel(Level.OFF);
	}

	private void printError(final Throwable e, final Args a) {
		printError("Error", e, a);
	}
	
	private void printError(
			final String msg,
			final Throwable e,
			final Args a) {
		err.println(msg + ": " + e.getMessage());
		if (a.verbose) {
			e.printStackTrace(err);
		}
	}

	private class Args {
		@Parameter(names = {"-h", "--help"}, help = true, description = "Display help.")
		private boolean help;
		
		@Parameter(names = {"-v", "--verbose"}, description = "Show error stacktraces.")
		private boolean verbose;
		
		@Parameter(names = {"-d", "--deploy"}, required = true,
				description = "Path to the auth deploy.cfg file.")
		private String deploy;
		
		@Parameter(names = {"-r", "--set-root-password"}, description =
				"Set the root user password. If the root account is disabled " +
				"it will be enabled with the enabling user set to the root user name.")
		private boolean setroot;
		
		@Parameter(names = {"--recanonicalize-display-names"}, description =
				"Recreate canonical search display names. This may be necessary after a version " +
				"update where the canonicalization algorithm has changed. " +
				"Records in the database are tagged with a flag with the current version once " +
				"they have been recanonicalized and will not be processed again unless the " +
				"flag is removed with --remove-recanonicalization-flag."
		)
		private boolean recanonicalizeDisplayNames;
		
		@Parameter(names = {"--remove-recanonicalization-flag"}, description =
				"Remove the flag denoting that a database user record's search display name " +
				"has been recanonicalized. Once removed, the recanonicalization algorithm " +
				"will update the record again if run."
		)
		private boolean removeRecanonicalizationFlag;
	}
}
