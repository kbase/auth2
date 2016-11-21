package us.kbase.auth2.cli;

import java.io.IOException;
import java.net.URI;
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
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import us.kbase.auth2.lib.Authentication;
import us.kbase.auth2.lib.Password;
import us.kbase.auth2.lib.exceptions.IdentityRetrievalException;
import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.IdentityProviderFactory;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.GlobusIdentityProvider.GlobusIdentityProviderConfigurator;
import us.kbase.auth2.lib.identity.GoogleIdentityProvider.GoogleIdentityProviderConfigurator;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.service.AuthBuilder;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthStartupConfig;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;
import us.kbase.auth2.service.kbase.KBaseAuthConfig;

public class AuthCLI {
	
	//TODO TEST
	//TODO JAVADOC
	//TODO TEST Move as much code as possible into a class to make things easier to test
	//TODO NOW Make 2 queries: 1) nexus to get email and full name, 2) globus-auth to get ID
	
	private static final String NAME = "manageauth";
	private static final String GLOBUS = "Globus";
	
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
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
			final AuthStartupConfig cfg = new KBaseAuthConfig(
					Paths.get(a.deploy), true);
			auth = new AuthBuilder(cfg, AuthExternalConfig.DEFAULT).getAuth();
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
			System.exit(0);
		}
		
		jc.usage();
	}



	private static void importUsers(final Args a, final Authentication auth) {
		if (a.token == null || a.token.trim().isEmpty()) {
			System.out.println("Must supply a token in the -t parameter " +
					"if importing users");
			System.exit(1);
		}
		final LocalDateTime now = LocalDateTime.now();
		final Path p = Paths.get(a.globus_users);
		final List<String> users = getUserList(a, p);
		final Client cli = ClientBuilder.newClient();
		int success = 0;
		for (final String user: users) {
			if (user.isEmpty()) {
				continue;
			}
			System.out.println("Importing user " + user);
			final RemoteIdentity ri;
			try {
				ri = getGlobusNexusIdentity(cli, a.token, user);
			} catch (IdentityRetrievalException | IOException e) {
				//TODO IMPORT if this happens, make an account from the v2 API. Write the user finding script first though.
				error("\tError in identity retrieval for user " + user,
						e, a, true);
				continue;
			}
			System.out.println("\tID       : " + ri.getRemoteID().getId());
			System.out.println("\tUsername : " + ri.getDetails().getUsername());
			System.out.println("\tFull name: " + ri.getDetails().getFullname());
			System.out.println("\tEmail    : " + ri.getDetails().getEmail());
			try {
				auth.importUser(ri);
				success++;
			} catch (UserExistsException | IllegalParameterException | AuthStorageException e) {
				error("\tError for user " + user, e, a, true);
			}
		}
		final Duration d = Duration.between(now, LocalDateTime.now());
		System.out.println(String.format(
				"Imported %s out of %s users from file %s in %s",
				success, users.size(), p, getDurationString(d)));
	}

	private static Object getDurationString(Duration d) {
		final long days = d.toDays();
		d = d.minusDays(days);
		final long hours = d.toHours();
		d = d.minusHours(hours);
		final long min = d.toMinutes();
		final long sec = d.minusMinutes(min).getSeconds();
		return String.format("%sD %sH %sM %sS", days, hours, min, sec);
	}



	private static RemoteIdentity getGlobusNexusIdentity(
			final Client cli,
			final String token,
			final String user)
			throws IdentityRetrievalException, IOException {
		
		//TODO NOW make the url a class var
		final URI idtarget = UriBuilder.fromPath(
				"https://nexus.api.globusonline.org/users/" + user)
				.build();
		
		final Map<String, Object> ret = globusGetRequest(cli, token, idtarget);
		final String username = ((String) ret.get("username"))
				+ "@globusid.org";
		final String fullname = (String) ret.get("full_name");
		final String email = (String) ret.get("email");
		final String id = (String) ret.get("identity_id");
		return new RemoteIdentity(
				new RemoteIdentityID(GLOBUS, id),
				new RemoteIdentityDetails(username, fullname, email));
	}
	
	private static Map<String, Object> globusGetRequest(
			final Client cli,
			final String accessToken,
			final URI idtarget)
			throws IdentityRetrievalException, IOException {
		final WebTarget wt = cli.target(idtarget);
		Response r = null;
		try {
			r = wt.request(MediaType.APPLICATION_JSON_TYPE)
					//TODO NOW class var
					.header("X-Globus-Goauthtoken", accessToken)
					.header("Accept", MediaType.APPLICATION_JSON)
					.get();
			//TODO TEST with 500s with HTML
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
				"(for example. foo@globusid.org). A Nexus Globus token for " +
				"an admin of the kbase_users group must be provided in the " +
				"-t option.")
		private String globus_users;
	}
}
