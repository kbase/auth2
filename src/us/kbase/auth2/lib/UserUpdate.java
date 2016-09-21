package us.kbase.auth2.lib;

public class UserUpdate {
	
	//TODO TEST
	//TODO JAVADOC
	//TODO INPUT needs input checking
	
	private String fullname;
	private String email;
	
	public UserUpdate() {}
	
	public UserUpdate withFullName(final String fullname) {
		this.fullname = get(fullname);
		return this;
	}
	
	public UserUpdate withEmail(final String email) {
		this.email = get(email);
		return this;
	}
	
	private String get(final String p) {
		return (p != null && p.isEmpty()) ? null : p;
	}

	public String getFullname() {
		return fullname;
	}

	public String getEmail() {
		return email;
	}
	
	public boolean hasUpdates() {
		return fullname != null && email != null;
	}
}
