package us.kbase.auth2.lib;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.base.Optional;

/*
@param  a string prefix with which to search. The prefix matches the start of the
* username or the start of any part of the whitespace tokenized display name.
* @param searchFields the fields on which the prefix search will be performed. If empty, the
* search will proceed on all fields.
* @param searchRoles limit the returned users to those with these roles.
* @param searchCustomRoles limit the returned users to those with these custom roles.

*/

public class UserSearchSpec {
	
	//TODO JAVADOC
	//TODO TEST
	
	private Optional<String> prefix = Optional.absent();
	private boolean searchUser = false;
	private boolean searchDisplayName = false;
	private final Set<Role> searchRoles = new HashSet<>();
	private final Set<String> searchCustomRoles = new HashSet<>();
	
	private UserSearchSpec() {}

	public Optional<String> getSearchPrefix() {
		return prefix;
	}

	public boolean isUserNameSearch() {
		return prefix.isPresent() && (searchUser || (!searchUser && !searchDisplayName));
	}

	public boolean isDisplayNameSearch() {
		return prefix.isPresent() && (searchDisplayName  || (!searchUser && !searchDisplayName));
	}
	
	public boolean isRoleSearch() {
		return !searchRoles.isEmpty();
	}
	
	public boolean isCustomRoleSearch() {
		return !searchCustomRoles.isEmpty();
	}

	public Set<Role> getSearchRoles() {
		return Collections.unmodifiableSet(searchRoles);
	}

	public Set<String> getSearchCustomRoles() {
		return Collections.unmodifiableSet(searchCustomRoles);
	}
	
	public SearchField orderBy() {
		if (isUserNameSearch()) {
			return SearchField.USERNAME;
		}
		if (isDisplayNameSearch()) {
			return SearchField.DISPLAYNAME;
		}
		if (isRoleSearch()) {
			return SearchField.ROLE;
		}
		return SearchField.CUSTOMROLE;
	}
	
	public enum SearchField {
		USERNAME,
		
		DISPLAYNAME,
		
		ROLE,
		
		CUSTOMROLE;
	}
	
	public static Builder getBuilder() {
		return new Builder();
	}

	public static class Builder {
		
		private UserSearchSpec uss = new UserSearchSpec();
		
		private Builder() {}
		
		public Builder withSearchPrefix(final String prefix) {
			if (prefix == null || prefix.trim().isEmpty()) {
				throw new IllegalArgumentException("Prefix cannot be null or the empty string");
			}
			uss.prefix = Optional.of(prefix);
			return this;
		}
		
		public Builder withSearchOnUserName(final boolean search) {
			uss.searchUser = search;
			return this;
		}
		
		public Builder withSearchOnDisplayname(final boolean search) {
			uss.searchDisplayName = search;
			return this;
		}
		
		public Builder withSearchOnRole(final Role role) {
			if (role == null) {
				throw new NullPointerException("role");
			}
			uss.searchRoles.add(role);
			return this;
		}
		
		public Builder withSearchOnCustomRole(final String customRole) {
			if (customRole == null || customRole.trim().isEmpty()) {
				throw new IllegalArgumentException(
						"Custom role cannot be null or the empty string");
			}
			uss.searchCustomRoles.add(customRole);
			return this;
		}
		
		public UserSearchSpec build() {
			return uss;
		}
	}
	
}
