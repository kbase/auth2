package us.kbase.test.auth2;

import static us.kbase.common.test.controllers.ControllerCommon.checkExe;
import static us.kbase.common.test.controllers.ControllerCommon.findFreePort;
import static us.kbase.common.test.controllers.ControllerCommon.makeTempDirs;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Scanner;
import java.util.stream.Collectors;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.zafarkhaja.semver.Version;
import org.apache.commons.io.FileUtils;


/** Q&D Utility to run a Mongo server for the purposes of testing from
 * Java.
 * @author gaprice@lbl.gov, sijiex@lbl.gov
 *
 */
public class MongoController {

    private final static String DATA_DIR = "data";

    private final static List<String> tempDirectories =
            new LinkedList<String>();
    static {
        tempDirectories.add(DATA_DIR);
    }

    private final static Version MONGO_DB_3 =
            Version.forIntegers(3,6,23);

    private final Path tempDir;

    private final Process mongo;

    private final int port;

    public MongoController(
            final String mongoExe,
            final Path rootTempDir)
            throws Exception {
        this(mongoExe, rootTempDir, false);
    }

    public MongoController(
            final String mongoExe,
            final Path rootTempDir,
            final boolean useWiredTiger)
            throws Exception {
        checkExe(mongoExe, "mongod server");
        tempDir = makeTempDirs(rootTempDir, "MongoController-", tempDirectories);
        port = findFreePort();
        Version dbVer = getMongoDBVer(mongoExe);
        List<String> command = getMongoServerStartCommand(mongoExe, useWiredTiger, dbVer);
        mongo = startProcess(command);
    }

    public int getServerPort() {
        return port;
    }

    public Path getTempDir() {
        return tempDir;
    }

    public void destroy(boolean deleteTempFiles) throws IOException {
        if (mongo != null) {
            mongo.destroy();
        }
        if (tempDir != null && deleteTempFiles) {
            FileUtils.deleteDirectory(tempDir.toFile());
        }
    }

    public static Version getMongoDBVer(final String mongoExe) throws IOException {

        // build MongoDB version check command
        List<String> command = new LinkedList<String>();
        command.addAll(Arrays.asList(mongoExe, "--version"));

        // start MongoDB version check process
        ProcessBuilder checkVerPb = new ProcessBuilder(command);
        Process checkVerProcess  = checkVerPb.start();

        // parse mongod --version output string
        String buildInfo = new BufferedReader(
                new InputStreamReader(checkVerProcess.getInputStream()))
                .lines()
                .collect(Collectors.joining("\n"))
                .split("\n", 2)[1];

        String buildInfoJsonStr = buildInfo.substring(buildInfo.indexOf("{"));
        ObjectMapper obj = new ObjectMapper();
        JsonNode node = obj.readTree(buildInfoJsonStr);
        JsonNode versionNode = node.get("version");

        System.out.println("MongoDB version: " + versionNode.textValue());
        checkVerProcess.destroy();
        return Version.valueOf(versionNode.textValue());
    }

    public List<String> getMongoServerStartCommand(final String mongoExe,
                                                   final boolean useWiredTiger,
                                                   final Version dbVer) {
        List<String> command = new LinkedList<String>();
        command.addAll(Arrays.asList(mongoExe, "--port", "" + port,
                "--dbpath", tempDir.resolve(DATA_DIR).toString()));

        // In version 3.6, the --nojournal option is deprecated
        if (dbVer.lessThanOrEqualTo(MONGO_DB_3)) {
            command.addAll(Arrays.asList("--nojournal"));
        }
        if (useWiredTiger) {
            command.addAll(Arrays.asList("--storageEngine", "wiredTiger"));
        }
        return command;
    }

    public Process startProcess(List<String> command) throws Exception {
        ProcessBuilder servpb = new ProcessBuilder(command)
                .redirectErrorStream(true)
                .redirectOutput(getTempDir().resolve("mongo.log").toFile());

        Process mongoProcess = servpb.start();
        Thread.sleep(3000); //wait for server to start up
        return mongoProcess;
    }

    public static void main(String[] args) throws Exception {
        us.kbase.common.test.controllers.mongo.MongoController ac = new us.kbase.common.test.controllers.mongo.MongoController(
                "/kb/runtime/bin/mongod",
                Paths.get("workspacetesttemp"));
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

