package us.kbase.auth2.cli;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.io.Console;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.slf4j.LoggerFactory;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParameterException;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import us.kbase.auth2.kbase.KBaseAuthConfig;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.exceptions.ErrorType;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.IllegalPasswordException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.providers.GlobusIdentityProviderFactory;
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
	private static final String GLOBUS = "Globus";
	private static final String GLOBUS_CLASS = GlobusIdentityProviderFactory.class.getName();
	
	private static final String GLOBUS_USER_URL = "https://nexus.api.globusonline.org/users/";
	private static final String GLOBUS_IDENTITES_PATH  = "/v2/api/identities";
	private static final String GLOBUS_NEXUS_TOKEN_HEADER = "X-Globus-Goauthtoken";
	
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
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
		nonNull(args, "args");
		nonNull(console, "console");
		nonNull(out, "out");
		nonNull(err, "err");
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
		try {
			// may need to be smarter here about figuring out the config implementation
			cfg = new KBaseAuthConfig(Paths.get(a.deploy), true);
			auth = new AuthBuilder(cfg, AuthExternalConfig.SET_DEFAULT).getAuth();
		} catch (AuthConfigurationException | StorageInitException e) {
			printError(e, a);
			return 1;
		}
		int ret = 0;
		if (a.setroot) {
			ret = setRootPassword(a, auth);
		
		//TODO REFACTOR remove this code and all dependent code
		
		/* The code below in the next block is not covered by tests and will be removed after
		 * the auth2 service is released in KBase production and the Globus endpoint shutdown.
		 */
		
		} else if (a.globus_users != null && !a.globus_users.trim().isEmpty()) {
			URL globusAPIURL = null;
			for (final IdentityProviderConfig idc: cfg.getIdentityProviderConfigs()) {
				if (idc.getIdentityProviderFactoryClassName().equals(GLOBUS_CLASS)) {
					globusAPIURL = idc.getApiURL();
				}
			}
			if (globusAPIURL == null) {
				err.println("No globus API url included in the deployment config file");
				ret = 1;
			}
			ret = importGlobusUsers(a, auth, globusAPIURL);
		} else {
			usage(jc);
		}
		return ret;
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

	private int importGlobusUsers(
			final Args a,
			final Authentication auth,
			final URL globusAPIURL) {
		if (a.nexusToken == null || a.nexusToken.trim().isEmpty()) {
			out.println("Must supply a Nexus token in the -n parameter " +
					"if importing users");
			return 1;
		}
		if (a.oauth2Token == null || a.oauth2Token.trim().isEmpty()) {
			out.println("Must supply an OAuth2 token in the -g parameter " +
					"if importing users");
			return 1;
		}
		final LocalDateTime now = LocalDateTime.now();
		final Path p = Paths.get(a.globus_users);
		final List<String> users;
		try {
			users = getUserList(a, p);
		} catch (NoSuchFileException e) {
			printError("No such file", e, a);
			return 1;
		} catch (AccessDeniedException e) {
			printError("Access denied", e, a);
			return 1;
		} catch (IOException e) {
			printError(e, a);
			return 1;
		}
		final Client cli = ClientBuilder.newClient();
		int success = 0;
		for (final String user: users) {
			out.println("Importing user " + user);
			
			final URI nexusUserURL = UriBuilder.fromPath(GLOBUS_USER_URL + user).build();
			String nexusEmail = null;
			String nexusFullname = null;
			try {
				final Map<String, Object> nexusRet = globusGetRequest(
						cli, a.nexusToken, nexusUserURL);
				// response includes a Globus v2 Oauth id but Globus says not to rely on it
				nexusFullname = ((String) nexusRet.get("full_name")).trim();
				nexusEmail = ((String) nexusRet.get("email")).trim();
			} catch (IdentityRetrievalException | IOException e) {
				if (printNexusErrorAndCheckIfFatal(user, a, e)) {
					continue;
				}
			}
			final RemoteIdentity ri;
			try {
				ri = getGlobusV2AuthIdentity(cli, globusAPIURL, a.oauth2Token,
						user + "@globusid.org", nexusFullname, nexusEmail);
			} catch (IdentityRetrievalException e) {
				printError("\tError in identity retrieval from Globus OAuth2 API for user " + user,
						e, a);
				continue;
			}
			out.println("\tID       : " + ri.getRemoteID().getProviderIdentityId());
			out.println("\tUsername : " + ri.getDetails().getUsername());
			out.println("\tFull name: " + ri.getDetails().getFullname());
			out.println("\tEmail    : " + ri.getDetails().getEmail());
			try {
				auth.importUser(getGlobusUserName(ri), ri);
				success++;
			} catch (UserExistsException | IllegalParameterException | IdentityLinkedException |
					AuthStorageException e) {
				printError("\tError for user " + user, e, a);
			}
		}
		final Duration d = Duration.between(now, LocalDateTime.now());
		out.println(String.format("Imported %s out of %s users from file %s in %s",
				success, users.size(), p, getDurationString(d)));
		return 0;
	}

	private UserName getGlobusUserName(final RemoteIdentity ri)
			throws IllegalParameterException {
		String username = ri.getDetails().getUsername();
		/* Do NOT otherwise change the username here - this is importing
		 * existing users, and so changing the username will mean erroneous
		 * resource assignments
		 */
		if (username.contains("@")) {
			username = username.split("@")[0];
			if (username.trim().isEmpty()) {
				throw new IllegalParameterException(ErrorType.ILLEGAL_USER_NAME,
						ri.getDetails().getUsername());
			}
		}
		try {
			return new UserName(username);
		} catch (MissingParameterException e) {
			throw new RuntimeException("Impossible", e);
		}
	}

	private boolean printNexusErrorAndCheckIfFatal(
			final String user,
			final Args a,
			final Exception e) {
		boolean skip = false;
		String append = "getting data soley from Globus OAuth V2 API";
		if (e instanceof IdentityRetrievalException) {
			if (((IdentityRetrievalException) e).getMessage().endsWith("User does not exist")) {
				skip = true;
				append = "skipping user";
			}
		}
		printError("\tError in identity retrieval from Globus Nexus API for user " + user + 
				", " + append, e, a);
		return skip;
	}

	private RemoteIdentity getGlobusV2AuthIdentity(
			final Client cli,
			final URL globusAPIURL,
			final String globusOAuthV2Token,
			final String username,
			final String nexusFullname,
			final String nexusEmail) throws IdentityRetrievalException {
		/* we use the globusV2 OAuth full name & email if it exists, otherwise use Nexus
		 * we don't check for used / unused status because the nexus user may not exist in globus
		 * Oauth v2. If so a v2 record will be created, but will be marked as unused. If a nexus
		 * user has used the v2 Oauth a record will already exist corresponding to the nexus
		 * account.
		 */
		final URI idtarget = UriBuilder.fromUri(toURI(globusAPIURL))
				.path(GLOBUS_IDENTITES_PATH)
				.queryParam("usernames", username)
				.build();
						
		final Map<String, Object> ret = globusOAuthV2GetRequest(
				cli, globusOAuthV2Token, idtarget);
		@SuppressWarnings("unchecked")
		final List<Map<String, String>> sids =
				(List<Map<String, String>>) ret.get("identities");
		final Map<String, String> id = sids.get(0);
		final String uid = (String) id.get("id");
		final String glusername = (String) id.get("username");
		final String name = (String) id.get("name");
		final String email = (String) id.get("email");
		final RemoteIdentity rid = new RemoteIdentity(
				new RemoteIdentityID(GLOBUS, uid),
				new RemoteIdentityDetails(glusername, name == null ? nexusFullname : name,
						email == null ? nexusEmail : email));
		return rid;
	}
	
	//Assumes valid URI in URL form
	private URI toURI(final URL url) {
		try {
			return url.toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	private Map<String, Object> globusOAuthV2GetRequest(
			final Client cli,
			final String accessToken,
			final URI idtarget)
			throws IdentityRetrievalException {
		final WebTarget wt = cli.target(idtarget);
		Response r = null;
		try {
			r = wt.request(MediaType.APPLICATION_JSON_TYPE)
					.header("Authorization", "Bearer " + accessToken)
					.get();
			@SuppressWarnings("unchecked")
			final Map<String, Object> mtemp = r.readEntity(Map.class);
			if (mtemp.containsKey("errors")) {
				@SuppressWarnings("unchecked")
				final List<Map<String, String>> errors =
						(List<Map<String, String>>) mtemp.get("errors");
				// just deal with the first error for now, change later if necc
				final Map<String, String> err = errors.get(0);
				throw new IdentityRetrievalException(String.format(
						"Identity provider returned an error: %s: %s; id: %s",
						err.get("code"), err.get("detail"), err.get("id")));
			}
			return mtemp;
		} finally {
			if (r != null) {
				r.close();
			}
		}
	}

	private Object getDurationString(Duration d) {
		final long days = d.toDays();
		d = d.minusDays(days);
		final long hours = d.toHours();
		d = d.minusHours(hours);
		final long min = d.toMinutes();
		final long sec = d.minusMinutes(min).getSeconds();
		return String.format("%sD %sH %sM %sS", days, hours, min, sec);
	}

	private Map<String, Object> globusGetRequest(
			final Client cli,
			final String accessToken,
			final URI idtarget)
			throws IdentityRetrievalException, IOException {
		final WebTarget wt = cli.target(idtarget);
		Response r = null;
		try {
			r = wt.request(MediaType.APPLICATION_JSON_TYPE)
					.header(GLOBUS_NEXUS_TOKEN_HEADER, accessToken)
					.header("Accept", MediaType.APPLICATION_JSON)
					.get();
			if (r.getStatus() == 404) { // other errors returned in JSON
				throw new IdentityRetrievalException("User does not exist");
			}
			// on error globus returns JSON with content-type = text/html
			// and jersey pukes if you directly try to read a Map
			@SuppressWarnings("unchecked")
			final Map<String, Object> mtemp = MAPPER.readValue(
					r.readEntity(String.class), Map.class);
			if (mtemp.containsKey("message")) {
				throw new IdentityRetrievalException(String.format(
						"Identity provider returned an error: %s: %s; id: %s",
						mtemp.get("code"), mtemp.get("message"),
						mtemp.get("request_id")));
			}
			return mtemp;
		} finally {
			if (r != null) {
				r.close();
			}
		}
	}

	private List<String> getUserList(final Args a, final Path p)
			throws IOException {
		final String userstr = new String(Files.readAllBytes(p), StandardCharsets.UTF_8);
		final List<String> users = new ArrayList<>(new HashSet<>(
				Arrays.asList(userstr.split("[\\s,;]"))));
		final Iterator<String> uiter = users.iterator();
		while (uiter.hasNext()) {
			if (uiter.next().isEmpty()) {
				uiter.remove();
			}
		}
		users.sort(null);
		return users;
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
				"other specified operations will be executed. If the root account is disabled " +
				"it will be enabled with the enabling user set to the root user name.")
		private boolean setroot;
		
		@Parameter(names = {"-n", "--nexus-token"}, description =
				"A Globus Nexus user token for use when importing users. Providing " +
				"a token without a users file does nothing.")
		private String nexusToken;
		
		@Parameter(names = {"-g", "--globus-token"}, description =
				"A Globus OAuth2 user token for use when importing users. Providing " +
				"a token without a users file does nothing.")
		private String oauth2Token;
		
		@Parameter(names = {"--import-globus-users"}, description = 
				"A UTF-8 encoded file of whitespace, comma, or semicolon " +
				"separated Globus user names in the Nexus format " +
				"(for example, kbasetest). A Nexus Globus token for " +
				"an admin of the kbase_users group must be provided in the " +
				"-n option, and a OAuth2 Globus token in the -g option. " +
				"Globus must be configured as an identity provider in the deploy.cfg file.")
		private String globus_users;
	}
}
