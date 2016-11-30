package us.kbase.auth2.lib;

public class Password {

	//TODO TEST
	//TODO JAVADOC
	
	private final char[] password;
	
	public Password(final char[] password) {
		//TODO PWD appropriate checking that the password is strong
		this.password = password;
	}
	
	public char[] getPassword() {
		return password;
	}
	
	public void clear() {
		for (int i = 0; i < password.length; i++) {
			password[i] = '0';
		}
	}
}
