package us.kbase.test.auth2.cli;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static us.kbase.auth2.Version.VERSION;
import static us.kbase.test.auth2.lib.storage.mongo.MongoStorageTestCommon.assertCorrectRecanonicalization;
import static us.kbase.test.auth2.lib.storage.mongo.MongoStorageTestCommon.assertNoRecanonicalizationFlag;
import static us.kbase.test.auth2.lib.storage.mongo.MongoStorageTestCommon.createUser;
import static us.kbase.test.auth2.lib.storage.mongo.MongoStorageTestCommon.setRecanonicalizedFlag;
import static us.kbase.test.auth2.lib.storage.mongo.MongoStorageTestCommon.trashCanonicalizationData;
import static us.kbase.test.auth2.TestCommon.assertClear;
import static us.kbase.test.auth2.TestCommon.list;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.bson.Document;
import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.cli.AuthCLI;
import us.kbase.auth2.cli.AuthCLI.ConsoleWrapper;
import us.kbase.auth2.cryptutils.PasswordCrypt;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.test.auth2.MongoStorageTestManager;
import us.kbase.test.auth2.TestCommon;

public class AuthCLITest {
	
	private final static String USAGE = 
			"Usage: manage_auth [options]\n" +
			"  Options:\n" +
			"  * -d, --deploy\n" +
			"       Path to the auth deploy.cfg file.\n" +
			"    -h, --help\n" +
			"       Display help.\n" +
			"       Default: false\n" +
			"    --recanonicalize-display-names\n" +
			"       Recreate canonical search display names. This may be necessary after a\n" +
			"       version update where the canonicalization algorithm has changed. Records in the\n" +
			"       database are tagged with a flag with the current version once they have been\n" +
			"       recanonicalized and will not be processed again unless the flag is removed with\n" +
			"       --remove-recanonicalization-flag.\n" +
			"       Default: false\n" +
			"    --remove-recanonicalization-flag\n" +
			"       Remove the flag denoting that a database user record's search display\n" +
			"       name has been recanonicalized. Once removed, the recanonicalization algorithm\n" +
			"       will update the record again if run.\n" +
			"       Default: false\n" +
			"    -r, --set-root-password\n" +
			"       Set the root user password. If the root account is disabled it will be\n" +
			"       enabled with the enabling user set to the root user name.\n" +
			"       Default: false\n" +
			"    -v, --verbose\n" +
			"       Show error stacktraces.\n" +
			"       Default: false\n";
	
	private final static Path WORK_DIR = Paths.get("").toAbsolutePath();
	
	private final static String DB_NAME = "authclitest";
	
	private static MongoStorageTestManager manager;
	private static MongoStorage storage;
	private static MongoDatabase db;

	
	@BeforeClass
	public static void beforeClass() throws Exception {
		manager = new MongoStorageTestManager(DB_NAME);
		storage = manager.storage;
		db = manager.db;
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		if (manager != null) {
			manager.destroy();
		}
	}
	
	@Before
	public void clearDB() throws Exception {
		manager.reset();
	}
	
	public class CollectingPrintStream extends PrintStream {
		
		public final List<Object> out = new LinkedList<>();
		
		public CollectingPrintStream() {
			super(new OutputStream() {
				
				@Override
				public void write(int b) throws IOException {
					throw new UnsupportedOperationException();
				}
			});
		}
		
		@Override
		public void println(final Object line) {
			out.add(line.toString());
		}
		
		@Override
		public void println(final String line) {
			out.add(line);
		}
		
	}
	
	@Test
	public void setRootPassword() throws Exception {
		setRootPassword("-r", "-d");
		setRootPassword("--set-root-password", "--deploy");
	}
	
	private void setRootPassword(final String param, final String deployparam) throws Exception {
		/* just checks that the record is created in the db. The detailed tests are in the
		 * main authentication class unit tests.
		 */
		
		final Path deploy = generateTempConfigFile();
		
		final ConsoleWrapper consoleMock = mock(ConsoleWrapper.class);
		
		final CollectingPrintStream out = new CollectingPrintStream();
		final CollectingPrintStream err = new CollectingPrintStream();
		
		final AuthCLI cli = new AuthCLI(new String[] {deployparam, deploy.toString(), param},
				consoleMock, out, err);
		
		final char[] pwd = "foobarbazbat".toCharArray();
		final char[] pwdcopy = Arrays.copyOf(pwd, pwd.length);
		when(consoleMock.hasConsole()).thenReturn(true);
		when(consoleMock.readPassword()).thenReturn(pwd);
		
		final int retcode = cli.execute();
		assertThat("incorrect error", err.out, is(Collections.emptyList()));
		assertThat("incorrect output", out.out, is(Arrays.asList("Enter the new root password:")));
		assertThat("incorrect return code", retcode, is(0));
		assertClear(pwd);
		
		final PasswordHashAndSalt creds = manager.storage.getPasswordHashAndSalt(UserName.ROOT);

		assertThat("incorrect creds", new PasswordCrypt().authenticate(
				pwdcopy, creds.getPasswordHash(), creds.getSalt()), is(true));
	}

	private Path generateTempConfigFile() throws IOException {
		final Ini ini = new Ini();
		final Section sec = ini.add("authserv2");
		sec.add("mongo-host", "localhost:" + manager.mongo.getServerPort());
		sec.add("mongo-db", DB_NAME);
		sec.add("token-cookie-name", "foobar");
		sec.add("template-dir", "templates");
		sec.add("environment-header", "X-MEN");
		final Path temp = TestCommon.getTempDir();
		final Path deploy = temp.resolve(Files.createTempFile(temp, "cli_test_deploy", ".cfg"));
		ini.store(deploy.toFile());
		deploy.toFile().deleteOnExit();
		System.out.println("Generated temporary config file " + deploy);
		return deploy;
	}
	
	@Test
	public void help() throws Exception {
		runCliPriorToPwdInput(new String[] {"-h"}, 0, Arrays.asList(USAGE),
				Collections.emptyList());
	}
	
	@Test
	public void parseFailNulls() throws Exception {
		final CollectingPrintStream out = new CollectingPrintStream();
		final CollectingPrintStream err = new CollectingPrintStream();
		final ConsoleWrapper console = mock(ConsoleWrapper.class);
		
		failConstructCLI(null, console, out, err, new NullPointerException("args"));
		failConstructCLI(new String[] {}, null, out, err, new NullPointerException("console"));
		failConstructCLI(new String[] {}, console, null, err, new NullPointerException("out"));
		failConstructCLI(new String[] {}, console, out, null, new NullPointerException("err"));
	}
	
	@Test
	public void parseFailNoArgs() throws Exception {
		runCliPriorToPwdInput(new String[] {}, 1, Collections.emptyList(), Arrays.asList(
				"Error: The following option is required: -d, --deploy "));
	}
	
	@Test
	public void parseFailVerboseOnly() throws Exception {
		runCliPriorToPwdInput(new String[] {"-v"}, 1, Collections.emptyList(), Arrays.asList(
				"Error: The following option is required: -d, --deploy ",
				"com.beust.jcommander.ParameterException: " +
					"The following option is required: -d, --deploy "), 2);
	}

	@Test
	public void parseFailNonsenseArgs() throws Exception {
		runCliPriorToPwdInput(new String[] {"foobarbazbat"}, 1, Collections.emptyList(),
				Arrays.asList("Error: Was passed main parameter 'foobarbazbat' " +
						"but no main parameter was defined"));
	}
	
	@Test
	public void parseInvalidConfigFile() throws Exception {
		runCliPriorToPwdInput(new String[] {"-d", "imreallyhopingthisfiledoesntexist"}, 1,
				Collections.emptyList(),
				Arrays.asList("Error: Could not read configuration file " +
						WORK_DIR + "/imreallyhopingthisfiledoesntexist: " +
						WORK_DIR + "/imreallyhopingthisfiledoesntexist " +
						"(No such file or directory)"));
		
	}
	
	@Test
	public void parseInvalidConfigFileVerbose() throws Exception {
		runCliPriorToPwdInput(new String[] {"-v", "-d", "imreallyhopingthisfiledoesntexist"}, 1,
				Collections.emptyList(),
				Arrays.asList("Error: Could not read configuration file " +
						WORK_DIR + "/imreallyhopingthisfiledoesntexist: " +
						WORK_DIR + "/imreallyhopingthisfiledoesntexist " +
						"(No such file or directory)",
						"us.kbase.auth2.service.exceptions.AuthConfigurationException: " +
						"Could not read configuration file " +
						WORK_DIR + "/imreallyhopingthisfiledoesntexist: " +
						WORK_DIR + "/imreallyhopingthisfiledoesntexist " +
						"(No such file or directory)"),
				2);
	}
	
	@Test
	public void authStartupFail() throws Exception {
		manager.db.getCollection("config").updateOne(new Document("schema", "schema"),
				new Document("$set", new Document("schemaver", 40)
					.append("schema", "schema")
					.append("inupdate", false)));
		
		final Path deploy = generateTempConfigFile();
		runCliPriorToPwdInput(new String[] {"-d", deploy.toString()}, 1,
				Collections.emptyList(),
				Arrays.asList("Error: Incompatible database schema. Server is v1, DB is v40"));
	}
	
	@Test
	public void incompleteArgsUsage() throws Exception {
		final Path deploy = generateTempConfigFile();
		runCliPriorToPwdInput(new String[] {"-d", deploy.toString()}, 0,
				Arrays.asList(USAGE), Collections.emptyList());
	}
	
	@Test
	public void nullConsole() throws Exception {
		final Path deploy = generateTempConfigFile();
		final ConsoleWrapper consoleMock = mock(ConsoleWrapper.class);
		when(consoleMock.hasConsole()).thenReturn(false);
		runCliPriorToPwdInput(new String[] {"-d", deploy.toString(), "-r"}, 1,
				Collections.emptyList(),
				Arrays.asList("No console available for entering password. Aborting."),
				consoleMock);
	}
	
	@Test
	public void noPassword() throws Exception {
		final Path deploy = generateTempConfigFile();
		final ConsoleWrapper consoleMock = mock(ConsoleWrapper.class);
		when(consoleMock.hasConsole()).thenReturn(true);
		when(consoleMock.readPassword()).thenReturn(null).thenReturn(new char[0]);
		
		runCliPriorToPwdInput(new String[] {"-d", deploy.toString(), "-r"}, 1,
				Arrays.asList("Enter the new root password:"),
				Arrays.asList("No password provided"),
				consoleMock);
		runCliPriorToPwdInput(new String[] {"-d", deploy.toString(), "-r"}, 1,
				Arrays.asList("Enter the new root password:"),
				Arrays.asList("No password provided"),
				consoleMock);
	}
	
	@Test
	public void illegalPassword() throws Exception {
		final Path deploy = generateTempConfigFile();
		final ConsoleWrapper consoleMock = mock(ConsoleWrapper.class);
		when(consoleMock.hasConsole()).thenReturn(true);
		when(consoleMock.readPassword()).thenReturn("short".toCharArray()).thenReturn(null);
		
		runCliPriorToPwdInput(new String[] {"-d", deploy.toString(), "-r"}, 1,
				Arrays.asList("Enter the new root password:"),
				Arrays.asList("Error: 30030 Illegal password: Password is not strong enough. " +
						"A word by itself is easy to guess."),
				consoleMock);
	}
	
	@Test
	public void illegalPasswordVerbose() throws Exception {
		final Path deploy = generateTempConfigFile();
		final ConsoleWrapper consoleMock = mock(ConsoleWrapper.class);
		when(consoleMock.hasConsole()).thenReturn(true);
		when(consoleMock.readPassword()).thenReturn("short".toCharArray()).thenReturn(null);
		
		runCliPriorToPwdInput(new String[] {"-d", deploy.toString(), "-r", "-v"}, 1,
				Arrays.asList("Enter the new root password:"),
				Arrays.asList("Error: 30030 Illegal password: Password is not strong enough. " +
						"A word by itself is easy to guess.",
						"us.kbase.auth2.lib.exceptions.IllegalPasswordException: " +
								"30030 Illegal password: Password is not strong enough. " +
								"A word by itself is easy to guess."),
				consoleMock, 2);
	}
	
	@Test
	public void removeRecanonicalizationFlags() throws Exception {
		final Path deploy = generateTempConfigFile();

		createUser(storage, "user1", "wowbagger-the-prolonged", 1);
		createUser(storage, "user2", "that one gu.y", 2);
		createUser(storage, "user3", "oh hooray!", 3);
		setRecanonicalizedFlag(db, "user1", VERSION.replace(".", "_"));
		setRecanonicalizedFlag(db, "user3", VERSION.replace(".", "_"));
		runCliPriorToPwdInput(
				new String[] {"-d", deploy.toString(), "--remove-recanonicalization-flag"},
				0,
				Arrays.asList("Removed 2 recanonicalization flags for version " + VERSION),
				Collections.emptyList());
		
		assertNoRecanonicalizationFlag(db, "user1");
		assertNoRecanonicalizationFlag(db, "user2");
		assertNoRecanonicalizationFlag(db, "user3");
	}
	
	@Test
	public void recanonicalizeDisplayNames() throws Exception {
		final Path deploy = generateTempConfigFile();
		
		createUser(storage, "user1", "wowbagger-the-prolonged", 1);
		createUser(storage, "user2", "that one gu.y", 2);
		createUser(storage, "user3", "oh hooray!", 3);
		trashCanonicalizationData(db, "user1");
		trashCanonicalizationData(db, "user2");
		trashCanonicalizationData(db, "user3");
		runCliPriorToPwdInput(
				new String[] {"-d", deploy.toString(), "--recanonicalize-display-names"},
				0,
				Arrays.asList("Recanonicalized 3 user display names"),
				Collections.emptyList());
		
		final String version = VERSION.replace(".", "_");
		assertCorrectRecanonicalization(
				db, "user1", list("wowbagger", "the", "prolonged"), version);
		assertCorrectRecanonicalization(db, "user2", list("that", "one", "guy"), version);
		assertCorrectRecanonicalization(db, "user3", list("oh", "hooray"), version);
	}

	private void runCliPriorToPwdInput(
			final String[] args,
			final int retcode,
			final List<String> out,
			final List<String> err) {
		runCliPriorToPwdInput(args, retcode, out, err, -1);
	}
	
	private void runCliPriorToPwdInput(
			final String[] args,
			final int retcode,
			final List<String> out,
			final List<String> err,
			final ConsoleWrapper consoleMock) {
		runCliPriorToPwdInput(args, retcode, out, err, consoleMock, -1);
	}
	
	private void runCliPriorToPwdInput(
			final String[] args,
			final int retcode,
			final List<String> out,
			final List<String> err,
			final int numErrLines) {
		final ConsoleWrapper consoleMock = mock(ConsoleWrapper.class);
		runCliPriorToPwdInput(args, retcode, out, err, consoleMock, numErrLines);
	}
	
	private void runCliPriorToPwdInput(
			final String[] args,
			final int retcode,
			final List<String> out,
			final List<String> err,
			final ConsoleWrapper consoleMock,
			final int numErrLines) {
		final CollectingPrintStream outs = new CollectingPrintStream();
		final CollectingPrintStream errs = new CollectingPrintStream();
		
		final int ret = new AuthCLI(args, consoleMock, outs, errs).execute();
		
		List<Object> errfinal = errs.out;
		if (numErrLines > 0) {
			errfinal = errfinal.subList(0, numErrLines);
		}
		
		assertThat("incorrect output", outs.out, is(out));
		assertThat("incorrect error", errfinal, is(err));
		assertThat("incorrect ret", ret, is(retcode));
	}

	private void failConstructCLI(
			final String[] args,
			final ConsoleWrapper consoleMock,
			final CollectingPrintStream out,
			final CollectingPrintStream err,
			final Exception e) {
		try {
			new AuthCLI(args, consoleMock, out, err);
			fail("expected exception");
		} catch (Exception got) {
			TestCommon.assertExceptionCorrect(got, e);
		}
	}
}
