package us.kbase.auth2.cli;

import java.io.IOException;
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
import us.kbase.auth2.lib.exceptions.MissingParameterException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityDetails;
import us.kbase.auth2.lib.identity.RemoteIdentityID;
import us.kbase.auth2.lib.identity.IdentityProviderConfig;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.storage.exceptions.StorageInitException;
import us.kbase.auth2.service.AuthBuilder;
import us.kbase.auth2.service.AuthExternalConfig;
import us.kbase.auth2.service.AuthStartupConfig;
import us.kbase.auth2.service.exceptions.AuthConfigurationException;

public class AuthCLI {
	
	//TODO TEST
	//TODO JAVADOC
	//TODO TEST Move as much code as possible into a class to make things easier to test, will require significant refactoring
	
	private static final String NAME = "manageauth";
	private static final String GLOBUS = "Globus";
	
	private static final String GLOBUS_USER_URL = "https://nexus.api.globusonline.org/users/";
	private static final String GLOBUS_IDENTITES_PATH  = "/v2/api/identities";
	private static final String GLOBUS_NEXUS_TOKEN_HEADER = "X-Globus-Goauthtoken";
	
	private static final ObjectMapper MAPPER = new ObjectMapper();
	
	public static void main(String[] args) {
		quietLogger();
		
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
		final AuthStartupConfig cfg;
		try {
			cfg = new KBaseAuthConfig(Paths.get(a.deploy), true);
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
			URL globusAPIURL = null;
			for (final IdentityProviderConfig idc: cfg.getIdentityProviderConfigs()) {
				if (idc.getIdentityProviderFactoryClassName().equals(GLOBUS)) {
					globusAPIURL = idc.getApiURL();
				}
			}
			if (globusAPIURL == null) {
				System.out.println("No globus API url included in the deployment config file");
				System.exit(1);
			}
			importGlobusUsers(a, auth, globusAPIURL);
			System.exit(0);
		}
		
		jc.usage();
	}

	private static void importGlobusUsers(
			final Args a,
			final Authentication auth,
			final URL globusAPIURL) {
		if (a.nexusToken == null || a.nexusToken.trim().isEmpty()) {
			System.out.println("Must supply a Nexus token in the -n parameter " +
					"if importing users");
			System.exit(1);
		}
		if (a.oauth2Token == null || a.oauth2Token.trim().isEmpty()) {
			System.out.println("Must supply an OAuth2 token in the -g parameter " +
					"if importing users");
			System.exit(1);
		}
		final LocalDateTime now = LocalDateTime.now();
		final Path p = Paths.get(a.globus_users);
		final List<String> users = getUserList(a, p);
		final Client cli = ClientBuilder.newClient();
		int success = 0;
		for (final String user: users) {
			System.out.println("Importing user " + user);
			
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
				error("\tError in identity retrieval from Globus OAuth2 API for user " + user,
						e, a, true);
				continue;
			}
			System.out.println("\tID       : " + ri.getRemoteID().getId());
			System.out.println("\tUsername : " + ri.getDetails().getUsername());
			System.out.println("\tFull name: " + ri.getDetails().getFullname());
			System.out.println("\tEmail    : " + ri.getDetails().getEmail());
			try {
				auth.importUser(getGlobusUserName(ri), ri);
				success++;
			} catch (UserExistsException | IllegalParameterException | IdentityLinkedException |
					AuthStorageException e) {
				error("\tError for user " + user, e, a, true);
			}
		}
		final Duration d = Duration.between(now, LocalDateTime.now());
		System.out.println(String.format("Imported %s out of %s users from file %s in %s",
				success, users.size(), p, getDurationString(d)));
	}

	private static UserName getGlobusUserName(final RemoteIdentity ri)
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

	private static boolean printNexusErrorAndCheckIfFatal(
			final String user,
			final Args a,
			final Exception e) {
		boolean skip = false;
		String append = "getting data soley from Globus OAuth V2 API";
		if (e instanceof IdentityRetrievalException) {
			if (((IdentityRetrievalException) e).getMessage().endsWith("User does not exist")) {
				skip = true;
				append = "skipping user";
				System.out.println("msg");
			}
		}
		error("\tError in identity retrieval from Globus Nexus API for user " + user + 
				", " + append, e, a, true);
		return skip;
	}

	private static RemoteIdentity getGlobusV2AuthIdentity(
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
	private static URI toURI(final URL url) {
		try {
			return url.toURI();
		} catch (URISyntaxException e) {
			throw new RuntimeException("This should be impossible", e);
		}
	}
	
	private static Map<String, Object> globusOAuthV2GetRequest(
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
			//TODO TEST with 500s with HTML
			@SuppressWarnings("unchecked")
			final Map<String, Object> mtemp = r.readEntity(Map.class);
			//TODO IDPROVERR handle {error=?} in object and check response code - partial implementation below
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

	private static Object getDurationString(Duration d) {
		final long days = d.toDays();
		d = d.minusDays(days);
		final long hours = d.toHours();
		d = d.minusHours(hours);
		final long min = d.toMinutes();
		final long sec = d.minusMinutes(min).getSeconds();
		return String.format("%sD %sH %sM %sS", days, hours, min, sec);
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
					.header(GLOBUS_NEXUS_TOKEN_HEADER, accessToken)
					.header("Accept", MediaType.APPLICATION_JSON)
					.get();
			if (r.getStatus() == 404) { // other errors returned in JSON
				throw new IdentityRetrievalException("User does not exist");
			}
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
		final Iterator<String> uiter = users.iterator();
		while (uiter.hasNext()) {
			if (uiter.next().isEmpty()) {
				uiter.remove();
			}
		}
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
				"-t option, and a OAuth2 Globus token in the -g option. " +
				"Globus must be configured as an identity provider in the deploy.cfg file.")
		private String globus_users;
	}
}
