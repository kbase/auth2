package us.kbase.test.auth2;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.bson.Document;
import org.ini4j.Ini;

import com.mongodb.client.MongoDatabase;

import us.kbase.auth2.lib.Password;
import us.kbase.common.test.TestException;

public class TestCommon {

	public static final String MONGOEXE = "test.mongo.exe";
	public static final String MONGO_USE_WIRED_TIGER = "test.mongo.wired_tiger";
	
	public static final String TEST_TEMP_DIR = "test.temp.dir";
	public static final String KEEP_TEMP_DIR = "test.temp.dir.keep";
	
	public static final String TEST_CONFIG_FILE_PROP_NAME = "AUTH2_TEST_CONFIG";
	public static final String TEST_CONFIG_FILE_SECTION = "auth2test";
	
	public static final String LONG101;
	public static final String LONG1001;
	static {
		final StringBuilder sb = new StringBuilder();
		for (int i = 0; i < 100; i++) {
			sb.append("a");
		}
		final String s100 = sb.toString();
		final StringBuilder sb2 = new StringBuilder();
		for (int i = 0; i < 100; i++) {
			sb2.append(s100);
		}
		LONG101 = s100 + "a";
		LONG1001 = sb2.toString() + "a";
	}
	
	private static Map<String, String> testConfig = null;
	
	public static void stfuLoggers() {
		java.util.logging.Logger.getLogger("com.mongodb")
				.setLevel(java.util.logging.Level.OFF);
		// these don't work to shut off the jetty logger
		((ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory
				.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME))
				.setLevel(ch.qos.logback.classic.Level.OFF);
		System.setProperty("org.eclipse.jetty.LEVEL", "OFF");
		System.setProperty("us.kbase.LEVEL", "OFF");
	}
	
	public static void assertExceptionCorrect(
			final Exception got,
			final Exception expected) {
		assertThat("incorrect exception. trace:\n" + ExceptionUtils.getStackTrace(got),
				got.getMessage(), is(expected.getMessage()));
		assertThat("incorrect exception type", got, instanceOf(expected.getClass()));
	}
	
	public static void assertExceptionMessageContains(
			final Exception got,
			final String expectedMessagePart) {
		assertThat("incorrect exception message. trace:\n" + ExceptionUtils.getStackTrace(got),
				got.getMessage(), containsString(expectedMessagePart));
	}
	
	/** See https://gist.github.com/vorburger/3429822
	 * Returns a free port number on localhost.
	 *
	 * Heavily inspired from org.eclipse.jdt.launching.SocketUtil (to avoid a
	 * dependency to JDT just because of this).
	 * Slightly improved with close() missing in JDT. And throws exception
	 * instead of returning -1.
	 *
	 * @return a free port number on localhost
	 * @throws IllegalStateException if unable to find a free port
	 */
	public static int findFreePort() {
		ServerSocket socket = null;
		try {
			socket = new ServerSocket(0);
			socket.setReuseAddress(true);
			int port = socket.getLocalPort();
			try {
				socket.close();
			} catch (IOException e) {
				// Ignore IOException on close()
			}
			return port;
		} catch (IOException e) {
		} finally {
			if (socket != null) {
				try {
					socket.close();
				} catch (IOException e) {
				}
			}
		}
		throw new IllegalStateException("Could not find a free TCP/IP port");
	}
	
	@SafeVarargs
	public static <T> Set<T> set(T... objects) {
		return new HashSet<T>(Arrays.asList(objects));
	}
	
	public static void assertClear(final byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			if (bytes[i] != 0) {
				fail(String.format("found non-zero byte at position %s: %s", i, bytes[i]));
			}
		}
	}
	
	public static void assertClear(final Password p) {
		assertClear(p.getPassword());
	}
	
	public static void assertClear(final char[] chars) {
		for (int i = 0; i < chars.length; i++) {
			if (chars[i] != '0') {
				fail(String.format("found char != '0' at postion %s: %s", i, chars[i]));
			}
		}
	}
	
	
	public static Path getMongoExe() {
		return Paths.get(getTestProperty(MONGOEXE)).toAbsolutePath().normalize();
	}

	public static Path getTempDir() {
		return Paths.get(getTestProperty(TEST_TEMP_DIR)).toAbsolutePath().normalize();
	}
	
	public static boolean isDeleteTempFiles() {
		return !"true".equals(getTestProperty(KEEP_TEMP_DIR));
	}

	public static boolean useWiredTigerEngine() {
		return "true".equals(System.getProperty(MONGO_USE_WIRED_TIGER));
	}
	
	private static String getTestProperty(final String propertyKey) {
		getTestConfig();
		final String prop = testConfig.get(propertyKey);
		if (prop == null || prop.trim().isEmpty()) {
			throw new TestException(String.format(
					"Property %s in section %s of test file %s is missing",
					propertyKey, TEST_CONFIG_FILE_SECTION, getConfigFilePath()));
		}
		return prop;
	}

	private static void getTestConfig() {
		if (testConfig != null) {
			return;
		}
		final Path testCfgFilePath = getConfigFilePath();
		final Ini ini;
		try {
			ini = new Ini(testCfgFilePath.toFile());
		} catch (IOException ioe) {
			throw new TestException(String.format(
					"IO Error reading the test configuration file %s: %s",
					testCfgFilePath, ioe.getMessage()), ioe);
		}
		testConfig = ini.get(TEST_CONFIG_FILE_SECTION);
		if (testConfig == null) {
			throw new TestException(String.format("No section %s found in test config file %s",
					TEST_CONFIG_FILE_SECTION, testCfgFilePath));
		}
	}

	private static Path getConfigFilePath() {
		final String testCfgFilePathStr = System.getProperty(TEST_CONFIG_FILE_PROP_NAME);
		if (testCfgFilePathStr == null || testCfgFilePathStr.trim().isEmpty()) {
			throw new TestException(String.format("Cannot get the test config file path." +
					" Ensure the java system property %s is set to the test config file location.",
					TEST_CONFIG_FILE_PROP_NAME));
		}
		return Paths.get(testCfgFilePathStr).toAbsolutePath().normalize();
	}
	
	public static void destroyDB(MongoDatabase db) {
		for (String name: db.listCollectionNames()) {
			if (!name.startsWith("system.")) {
				// dropping collection also drops indexes
				db.getCollection(name).deleteMany(new Document());
			}
		}
	}
	
	//http://quirkygba.blogspot.com/2009/11/setting-environment-variables-in-java.html
	@SuppressWarnings("unchecked")
	public static Map<String, String> getenv()
			throws NoSuchFieldException, SecurityException,
			IllegalArgumentException, IllegalAccessException {
		Map<String, String> unmodifiable = System.getenv();
		Class<?> cu = unmodifiable.getClass();
		Field m = cu.getDeclaredField("m");
		m.setAccessible(true);
		return (Map<String, String>) m.get(unmodifiable);
	}
}
