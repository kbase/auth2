package us.kbase.test.auth2.cli;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

import org.ini4j.Ini;
import org.ini4j.Profile.Section;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import com.mongodb.MongoClient;
import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.cli.AuthCLI;
import us.kbase.auth2.cli.AuthCLI.ConsoleWrapper;
import us.kbase.auth2.cryptutils.PasswordCrypt;
import us.kbase.auth2.lib.PasswordHashAndSalt;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.storage.mongo.MongoStorage;
import us.kbase.common.test.controllers.mongo.MongoController;
import us.kbase.test.auth2.TestCommon;

public class AuthCLITest {
	
	private final static String DB_NAME = "authclitest";

	private static MongoController mongo;
	private static MongoClient mc;
	private static MongoDatabase db;
	private static MongoStorage storage;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		TestCommon.stfuLoggers();
		mongo = new MongoController(TestCommon.getMongoExe().toString(),
				TestCommon.getTempDir(),
				TestCommon.useWiredTigerEngine());
		System.out.println(String.format("Testing against mongo excutable %s on port %s",
				TestCommon.getMongoExe(), mongo.getServerPort()));
		mc = new MongoClient("localhost:" + mongo.getServerPort());
		db = mc.getDatabase(DB_NAME);
		storage = new MongoStorage(db);
		
	}
	
	@AfterClass
	public static void tearDownClass() throws Exception {
		if (mc != null) {
			mc.close();
		}
		if (mongo != null) {
			try {
				mongo.destroy(TestCommon.isDeleteTempFiles());
			} catch (IOException e) {
				System.out.println("Error deleting temporarary files at: " +
						TestCommon.getTempDir());
				e.printStackTrace();
			}
		}
	}
	
	public class CollectingPrintStream extends PrintStream {
		
		public final List<String> out = new LinkedList<>();
		
		public CollectingPrintStream() {
			super(new OutputStream() {
				
				@Override
				public void write(int b) throws IOException {
					System.out.println("You screwed this up bud, this shouldn't happen");
					// do nothing
				}
			});
		}
		
		@Override
		public void println(final String line) {
			out.add(line);
		}
		
	}
	
	@Test
	public void setRootPassword() throws Exception {
		setRootPassword("-r");
		setRootPassword("--set-root-password");
	}
	
	private void setRootPassword(final String param) throws Exception {
		/* just checks that the record is created in the db. The detailed tests are in the
		 * main authentication class unit tests.
		 */
		
		final Ini ini = new Ini();
		final Section sec = ini.add("authserv2");
		sec.add("mongo-host", "localhost:" + mongo.getServerPort());
		sec.add("mongo-db", DB_NAME);
		sec.add("token-cookie-name", "foobar");
		final Path temp = TestCommon.getTempDir();
		final Path deploy = temp.resolve("cli_test_deploy.cfg");
		ini.store(deploy.toFile());
		
		final ConsoleWrapper consoleMock = mock(ConsoleWrapper.class);
		
		//TODO NOW TEST error conditions
		
		final CollectingPrintStream out = new CollectingPrintStream();
		
		final CollectingPrintStream err = new CollectingPrintStream();
		
		final AuthCLI cli = new AuthCLI(new String[] {"-d", deploy.toString(), param},
				consoleMock, out, err);
		
		final char[] pwd = "foobarbazbat".toCharArray();
		final char[] pwdcopy = Arrays.copyOf(pwd, pwd.length);
		when(consoleMock.readPassword()).thenReturn(pwd);
		
		final int retcode = cli.execute();
		assertThat("incorrect error", err.out, is(Collections.emptyList()));
		assertThat("incorrect output", out.out, is(Arrays.asList("Enter the new root password:")));
		assertThat("incorrect return code", retcode, is(0));
		TestCommon.assertClear(pwd);
		
		final PasswordHashAndSalt creds = storage.getPasswordHashAndSalt(UserName.ROOT);

		assertThat("incorrect creds", new PasswordCrypt().authenticate(
				pwdcopy, creds.getPasswordHash(), creds.getSalt()), is(true));
	}
}
