package us.kbase.auth2;

import java.io.InputStream;
import java.util.Scanner;

public class GitCommit {
	
	//TODO JAVADOC
	
	// can't really test this since the file should be baked into the jar or war

	public static final String COMMIT;
	
	private static final String COMMIT_FILE_NAME = "gitcommit";
	
	static {
		final InputStream is = GitCommit.class.getResourceAsStream(COMMIT_FILE_NAME);
		String commit = null;
		if (is == null) {
			commit = "Missing git commit file " + COMMIT_FILE_NAME +
					", should be in " + GitCommit.class.getPackage().getName();
		} else {
			final Scanner s = new Scanner(is);
			s.useDelimiter("\\A");
			commit = s.hasNext() ? s.next() : "";
			s.close();
		}
		COMMIT = commit;
	}
	
}
