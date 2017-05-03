package us.kbase.test.auth2.service.ui;

import static org.junit.Assert.assertThat;

import org.mockito.ArgumentMatcher;

import us.kbase.common.test.RegexMatcher;

public class StateMatcher implements ArgumentMatcher<String> {

	public String capturedState = null;
	
	@Override
	public boolean matches(String state) {
		assertThat("invalid state value", state, RegexMatcher.matches("[A-Z2-7]{32}"));
		capturedState = state;
		return true;
	}

}
