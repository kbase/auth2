package us.kbase.test.auth2.service.ui;

import static org.junit.Assert.assertThat;

import org.mockito.ArgumentMatcher;

import us.kbase.common.test.RegexMatcher;

public class PKCEChallengeMatcher implements ArgumentMatcher<String> {
	
	public String capturedChallenge = null; 

	@Override
	public boolean matches(final String pkceChallenge) {
		assertThat("invalid PKCE challenge value",
				pkceChallenge, RegexMatcher.matches("[a-zA-Z0-9-_]{43}"));
		capturedChallenge = pkceChallenge;
		return true;
	}

}
