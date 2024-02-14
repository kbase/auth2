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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

import us.kbase.common.test.TestException;
import us.kbase.test.auth2.StandaloneAuthServer;

/** Q&D utility to run the auth server in test mode for use in testing rigs. Expected to
 * be packaged in a test jar with all dependencies and the templates in a /templates/ directory.
 */
public class AuthController {
	
	// hardcoded in build.gradle
	private static final String TEMPLATES_JAR_DIR = "kbase_auth2_templates";
	private static final String TEMPLATES_LIST_FILE = "templates.manifest";

	private static final String AUTH_CLASS = StandaloneAuthServer.class.getName();
	private static final String JAR_PATH = StandaloneAuthServer.class.getProtectionDomain()
			.getCodeSource().getLocation().getPath();
	
	private final Process auth;
	private final int port;
	private final Path tempDir;
	private final String version;
	
	public AuthController(
			final String mongoHost,
			final String mongoDatabase,
			final Path rootTempDir)
			throws Exception {
		this(mongoHost, mongoDatabase, rootTempDir, null, null);
	}
	
	public AuthController(
			final String mongoHost,
			final String mongoDatabase,
			final Path rootTempDir,
			final String mongoUser,
			final String mongoPwd)
			throws Exception {
		if (mongoUser == null ^ mongoPwd == null) {
			throw new TestException("Both or neither of the mongo user / pwd must be provided");
		}
		tempDir = makeTempDirs(rootTempDir, "AuthController-", Arrays.asList("templates"));
		port = findFreePort();
		System.out.println("Using classpath " + JAR_PATH);
		
		final Path templateDir = tempDir.resolve("templates");
		installTemplates(templateDir);
		
		final List<String> command = new ArrayList<>(Arrays.asList(
				"java",
				"-classpath", JAR_PATH,
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
	
	private void installTemplates(final Path templatesDir) throws IOException {
		final String templatesJarFileList = "/" + TEMPLATES_JAR_DIR + "/" + TEMPLATES_LIST_FILE;
		final List<String> templateFiles = new ArrayList<>();
		try (final InputStream templateFilesStream = getClass()
				.getResourceAsStream(templatesJarFileList)
		) {
			if (templateFilesStream == null) {
				throw new TestException(String.format(
						"Could not find template file list file %s in jar", templatesJarFileList));
			}
			final BufferedReader br = new BufferedReader(
					new InputStreamReader(templateFilesStream));
			br.lines().forEach(templateFile -> templateFiles.add(templateFile));
		}
		for (final String templateFileName: templateFiles) {
			final String templateJarPath = "/" + TEMPLATES_JAR_DIR + "/" + templateFileName;
			final Path templateTargetPath = templatesDir.resolve(templateFileName)
					.toAbsolutePath();
			try (
					final InputStream template = getClass()
							.getResourceAsStream(templateJarPath);
					final OutputStream target = Files.newOutputStream(templateTargetPath);
					
			) {
				if (template == null) {
					throw new TestException(String.format(
							"Could not find template file %s in jar", templateJarPath));
				}
				IOUtils.copy(template, target);
			}
		}
	}

}
