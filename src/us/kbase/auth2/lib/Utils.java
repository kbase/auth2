package us.kbase.auth2.lib;

import us.kbase.auth2.lib.exceptions.IllegalParameterException;
import us.kbase.auth2.lib.exceptions.MissingParameterException;

public class Utils {

	//TODO TESTS
	//TODO JAVADOC
	
	public static void checkString(final String s, final String name)
			throws MissingParameterException {
		try {
			checkString(s, name, -1);
		} catch (IllegalParameterException e) {
			throw new RuntimeException("Programming error: " +
					e.getMessage(), e);
		}
	}
	
	public static void checkString(
			final String s,
			final String name,
			final int max)
			throws MissingParameterException, IllegalParameterException {
		if (s == null || s.trim().isEmpty()) {
			throw new MissingParameterException("Missing parameter: " + name);
		}
		
		if (max > 0 && codePoints(s) > max) {
			throw new IllegalParameterException(
					name + " size greater than limit " + max);
		}
	}
	
	private static int codePoints(final String s) {
		return s.codePointCount(0, s.length());
	}
	public static void checkStringNoCheckedException(
			final String s,
			final String name) {
		if (s == null || s.trim().isEmpty()) {
			throw new IllegalArgumentException("Missing argument: " + name);
		}
	}

	// prevents overflows by returning max long if a + b > maxlong
	public static long addLong(final long a, final long b) {
		final long c;
		if (Long.MAX_VALUE - a < b) {
			c = Long.MAX_VALUE;
		} else {
			c = a + b;
		}
		return c;
	}
	
	public static void clear(final byte[] bytes) {
		for (int i = 0; i < bytes.length; i++) {
			bytes[i] = 0;
		}
	}
}
