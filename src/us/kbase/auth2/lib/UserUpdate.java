package us.kbase.auth2.lib;

import static us.kbase.auth2.lib.Utils.nonNull;

import java.util.Optional;
/** This class represents an update to a user's details as submitted by a user.
 * @author gaprice@lbl.gov
 *
 */
public class UserUpdate {
	
	private final Optional<DisplayName> displayName;
	private final Optional<EmailAddress> email;
	
	private UserUpdate(
			final Optional<DisplayName> displayName,
			final Optional<EmailAddress> email) {
		this.displayName = displayName;
		this.email = email;
	}
	
	/** Returns the display name for the update, or absent if no update is to be performed.
	 * @return the display name.
	 */
	public Optional<DisplayName> getDisplayName() {
		return displayName;
	}
	
	/** Returns the email address for the update, or absent if no update is to be performed.
	 * @return the email address.
	 */
	public Optional<EmailAddress> getEmail() {
		return email;
	}
	
	/** Returns whether this update instance contains any updates to be made.
	 * @return true if there are updates to be made, false otherwise.
	 */
	public boolean hasUpdates() {
		return displayName.isPresent() || email.isPresent();
	}
	
	/** Get a UserUpdate builder.
	 * @return a builder.
	 */
	public static Builder getBuilder() {
		return new Builder();
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((displayName == null) ? 0 : displayName.hashCode());
		result = prime * result + ((email == null) ? 0 : email.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		UserUpdate other = (UserUpdate) obj;
		if (displayName == null) {
			if (other.displayName != null) {
				return false;
			}
		} else if (!displayName.equals(other.displayName)) {
			return false;
		}
		if (email == null) {
			if (other.email != null) {
				return false;
			}
		} else if (!email.equals(other.email)) {
			return false;
		}
		return true;
	}

	/** A builder for a UserUpdate.
	 * @author gaprice@lbl.gov
	 *
	 */
	public static class Builder {
	
		private Optional<DisplayName> displayName = Optional.empty();
		private Optional<EmailAddress> email = Optional.empty();
		
		private Builder() {}

		/** Set the display name to be updated.
		 * @param displayName the name to be updated.
		 * @return this Builder.
		 */
		public Builder withDisplayName(final DisplayName displayName) {
			nonNull(displayName, "displayName");
			this.displayName = Optional.of(displayName);
			return this;
		}
		
		/** Set the email address to be updated.
		 * @param email the email address to be updated.
		 * @return this Builder.
		 */
		public Builder withEmail(final EmailAddress email) {
			nonNull(email, "email");
			this.email = Optional.of(email);
			return this;
		}
		
		/** Build the user update.
		 * @return a new UserUpdate.
		 */
		public UserUpdate build() {
			return new UserUpdate(displayName, email);
		}
	}
}
