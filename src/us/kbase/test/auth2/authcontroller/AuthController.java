package us.kbase.test.auth2.authcontroller;

import static us.kbase.common.test.controllers.ControllerCommon.findFreePort;
import static us.kbase.common.test.controllers.ControllerCommon.makeTempDirs;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;

import org.apache.commons.io.FileUtils;

import com.google.common.collect.ImmutableList;

import us.kbase.common.test.TestException;
import us.kbase.test.auth2.StandaloneAuthServer;

public class AuthController {
	
	private final static String AUTH_CLASS = StandaloneAuthServer.class.getName();
	private static final String JARS_FILE = "authjars";
	
	private final Process auth;
	private final int port;
	private final Path tempDir;
	
	public AuthController(
			final Path jarsDir,
			final String mongoHost,
			final String mongoDatabase,
			final Path rootTempDir)
			throws IOException, InterruptedException {
		final String classPath = getClassPath(jarsDir);
		tempDir = makeTempDirs(rootTempDir, "AuthController-", Collections.emptyList());
		port = findFreePort();
		
		final List<String> command = ImmutableList.of(
				"java",
				"-classpath", classPath,
				"-DAUTH2_TEST_MONGOHOST=" + mongoHost,
				"-DAUTH2_TEST_MONGODB=" + mongoDatabase,
				AUTH_CLASS,
				"" + port);
		final ProcessBuilder servpb = new ProcessBuilder(command)
				.redirectErrorStream(true)
				.redirectOutput(tempDir.resolve("auth.log").toFile());
		
		auth = servpb.start();
		// could make a loop checking for connection later
		Thread.sleep(10000); //wait for server to start up
	}
	
	public int getServerPort() {
		return port;
	}

	public Path getTempDir() {
		return tempDir;
	}

	public void destroy(boolean deleteTempFiles) throws IOException {
		if (auth != null) {
			auth.destroy();
		}
		if (tempDir != null && deleteTempFiles) {
			FileUtils.deleteDirectory(tempDir.toFile());
		}
	}

	private String getClassPath(final Path jarsDir) throws IOException {
		final InputStream is = getClass().getResourceAsStream(JARS_FILE);
		if (is == null) {
			throw new TestException("No auth versions file " + JARS_FILE);
		}
		final List<String> classpath = new LinkedList<>();
		try (final Reader r = new InputStreamReader(is)) {
			final BufferedReader br = new BufferedReader(r);
			String line;
			while ((line = br.readLine()) != null) {
				if (!line.trim().isEmpty() && !line.trim().startsWith("#")) {
					final Path jarPath = jarsDir.resolve(line);
					if (Files.notExists(jarPath)) {
						throw new TestException("Required jar does not exist: " + jarPath);

					}
					classpath.add(jarPath.toString());
				}
			}
		}
		return String.join(":", classpath);
	}
	
	public static void main(final String[] args) throws IOException, InterruptedException {
		final AuthController ac = new AuthController(
				Paths.get("/home/crusherofheads/localgit/jars/lib/jars"),
				"localhost:27017",
				"AuthController",
				Paths.get("authtesttemp"));
		System.out.println(ac.getServerPort());
		System.out.println(ac.getTempDir());
		Scanner reader = new Scanner(System.in);
		System.out.println("any char to shut down");
		//get user input for a
		reader.next();
		ac.destroy(false);
		reader.close();
	}

}
