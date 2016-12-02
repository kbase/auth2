package us.kbase.auth2.lib;

public class UserUpdate {
	
	//TODO TEST
	//TODO JAVADOC
	//TODO INPUT needs input checking
	
	private DisplayName displayName;
	private EmailAddress email;
	
	public UserUpdate() {}
	
	public UserUpdate withDisplayName(final DisplayName displayName) {
		this.displayName = displayName;
		return this;
	}
	
	public UserUpdate withEmail(final EmailAddress email) {
		this.email = email;
		return this;
	}
	
	public DisplayName getDisplayName() {
		return displayName;
	}

	public EmailAddress getEmail() {
		return email;
	}
	
	public boolean hasUpdates() {
		return displayName != null || email != null;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		builder.append("UserUpdate [displayName=");
		builder.append(displayName);
		builder.append(", email=");
		builder.append(email);
		builder.append("]");
		return builder.toString();
	}
}
