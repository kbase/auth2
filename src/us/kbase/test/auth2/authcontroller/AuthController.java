package us.kbase.test.auth2.authcontroller;

import static us.kbase.common.test.controllers.ControllerCommon.findFreePort;
import static us.kbase.common.test.controllers.ControllerCommon.makeTempDirs;
import static us.kbase.test.auth2.TestConfigurator.MONGO_HOST_KEY;
import static us.kbase.test.auth2.TestConfigurator.MONGO_DB_KEY;
import static us.kbase.test.auth2.TestConfigurator.MONGO_TEMPLATES_KEY;
import static us.kbase.test.auth2.TestConfigurator.MONGO_USER_KEY;
import static us.kbase.test.auth2.TestConfigurator.MONGO_PWD_KEY;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import us.kbase.common.test.TestException;
import us.kbase.test.auth2.StandaloneAuthServer;

public class AuthController {
	
	private final static String AUTH_CLASS = StandaloneAuthServer.class.getName();
	private static final String JARS_FILE = "authjars";
	
	private final Process auth;
	private final int port;
	private final Path tempDir;
	private final String version;
	
	public AuthController(
			final Path jarsDir,
			final String mongoHost,
			final String mongoDatabase,
			final Path rootTempDir)
			throws Exception {
		this(jarsDir, mongoHost, mongoDatabase, rootTempDir, null, null);
	}
	
	public AuthController(
			final Path jarsDir,
			final String mongoHost,
			final String mongoDatabase,
			final Path rootTempDir,
			final String mongoUser,
			final String mongoPwd)
			throws Exception {
		if (mongoUser == null ^ mongoPwd == null) {
			throw new TestException("Both or neither of the mongo user / pwd must be provided");
		}
		final String classPath = getClassPath(jarsDir);
		tempDir = makeTempDirs(rootTempDir, "AuthController-", Arrays.asList("templates"));
		port = findFreePort();
		
		final Path templateDir = tempDir.resolve("templates");
		installTemplates(jarsDir, templateDir);
		
		final List<String> command = new ArrayList<>(Arrays.asList(
				"java",
				"-classpath", classPath,
				"-D" + MONGO_HOST_KEY + "=" + mongoHost,
				"-D" + MONGO_DB_KEY + "=" + mongoDatabase,
				"-D" + MONGO_TEMPLATES_KEY + "=" + templateDir.toString()));
		if (mongoUser != null) {
			command.add("-D" + MONGO_USER_KEY + "=" + mongoUser);
			command.add("-D" + MONGO_PWD_KEY + "=" + mongoUser);
		}
		command.add(AUTH_CLASS);
		command.add("" + port);
		final ProcessBuilder servpb = new ProcessBuilder(command)
				.redirectErrorStream(true)
				.redirectOutput(tempDir.resolve("auth.log").toFile());
		
		auth = servpb.start();
		
		Exception startupError = null;
		String version = null;
		for (int i = 0; i < 40; i++) {
			Thread.sleep(1000); //wait for server to start up
			final HttpURLConnection authConn =
					(HttpURLConnection) new URL("http://localhost:" + port).openConnection();
			try {
				authConn.setRequestProperty("accept", "application/json");
				authConn.connect();
				if (authConn.getResponseCode() != 200) {
					try (final InputStream is = authConn.getErrorStream()) {
						startupError = new TestException(IOUtils.toString(is));
					}
				} else {
					try (final InputStream is = authConn.getInputStream()) {
						
						@SuppressWarnings("unchecked")
						final Map<String, Object> resp =
								new ObjectMapper().readValue(is, Map.class);
						version = (String) resp.get("version");
						startupError = null;
						break;
					}
				}
			} catch (Exception e) {
				startupError = e;
			}
		}
		if (startupError != null) {
			throw startupError;
		} else {
			this.version = version;
		}
		
	}
	
	public int getServerPort() {
		return port;
	}

	public Path getTempDir() {
		return tempDir;
	}
	
	public String getVersion() {
		return version;
	}

	public void destroy(boolean deleteTempFiles) throws IOException {
		if (auth != null) {
			auth.destroy();
		}
		if (tempDir != null && deleteTempFiles) {
			FileUtils.deleteDirectory(tempDir.toFile());
		}
	}
	
	private void installTemplates(final Path jarsDir, final Path templatesDir) throws IOException {
		final Path templateZipFile;
		try (final InputStream is = getJarsFileInputStream()) {
			final BufferedReader br = new BufferedReader(new InputStreamReader(is));
			//first line is zip file with templates
			templateZipFile = jarsDir.resolve(br.readLine().trim());
		}
		try (final ZipFile zf = new ZipFile(templateZipFile.toFile())) {
			for (Enumeration<? extends ZipEntry> e = zf.entries(); e.hasMoreElements();) {
				final ZipEntry ze = e.nextElement();
				if (ze.isDirectory()) {
					continue;
				}
				final Path zippath = Paths.get(ze.getName()).normalize();
				if (zippath.isAbsolute() || zippath.startsWith("..")) {
					throw new TestException("Zip file " + templateZipFile +
							" contains files outside the zip " +
							"directory - this is a sign of a malicious zip file.");
				}
				final Path file = templatesDir.resolve(zippath).toAbsolutePath();
				Files.createDirectories(file.getParent());
				Files.createFile(file);
				try (final OutputStream os = Files.newOutputStream(file);
						final InputStream zipinput = zf.getInputStream(ze)) {
					IOUtils.copy(zipinput, os);
				}
			}
		} catch (ZipException e) {
			throw new TestException("Unable to open the zip file " + templateZipFile, e);
		}

	}

	private String getClassPath(final Path jarsDir) throws IOException {
		final List<String> classpath = new LinkedList<>();
		try (final InputStream is = getJarsFileInputStream();) {
			final BufferedReader br = new BufferedReader(new InputStreamReader(is));
			br.readLine(); // discard first line, which has the templates zip file
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

	private InputStream getJarsFileInputStream() {
		final InputStream is = getClass().getResourceAsStream(JARS_FILE);
		if (is == null) {
			throw new TestException("No auth versions file " + JARS_FILE);
		}
		return is;
	}
	
	public static void main(final String[] args) throws Exception {
		final AuthController ac = new AuthController(
				Paths.get("/home/crushingismybusiness/github/mrcreosote/jars/lib/jars"),
				"localhost:27017",
				"AuthController",
				Paths.get("authtesttemp"),
				"auth",
				"auth");
		System.out.println(ac.getServerPort());
		System.out.println(ac.getTempDir());
		System.out.println(ac.getVersion());
		Scanner reader = new Scanner(System.in);
		System.out.println("any char to shut down");
		reader.next();
		ac.destroy(false);
		reader.close();
	}

}
