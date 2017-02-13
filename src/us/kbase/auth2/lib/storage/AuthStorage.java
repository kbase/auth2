package us.kbase.auth2.lib.storage;

import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import us.kbase.auth2.lib.AuthConfigSet;
import us.kbase.auth2.lib.AuthUser;
import us.kbase.auth2.lib.CustomRole;
import us.kbase.auth2.lib.DisplayName;
import us.kbase.auth2.lib.ExternalConfig;
import us.kbase.auth2.lib.ExternalConfigMapper;
import us.kbase.auth2.lib.LocalUser;
import us.kbase.auth2.lib.NewLocalUser;
import us.kbase.auth2.lib.NewUser;
import us.kbase.auth2.lib.Role;
import us.kbase.auth2.lib.SearchField;
import us.kbase.auth2.lib.UserName;
import us.kbase.auth2.lib.UserUpdate;
import us.kbase.auth2.lib.exceptions.ExternalConfigMappingException;
import us.kbase.auth2.lib.exceptions.IdentityLinkedException;
import us.kbase.auth2.lib.exceptions.LinkFailedException;
import us.kbase.auth2.lib.exceptions.NoSuchRoleException;
import us.kbase.auth2.lib.exceptions.NoSuchTokenException;
import us.kbase.auth2.lib.exceptions.NoSuchUserException;
import us.kbase.auth2.lib.exceptions.UnLinkFailedException;
import us.kbase.auth2.lib.exceptions.UserExistsException;
import us.kbase.auth2.lib.identity.RemoteIdentity;
import us.kbase.auth2.lib.identity.RemoteIdentityWithLocalID;
import us.kbase.auth2.lib.storage.exceptions.AuthStorageException;
import us.kbase.auth2.lib.token.HashedToken;
import us.kbase.auth2.lib.token.IncomingHashedToken;
import us.kbase.auth2.lib.token.TemporaryHashedToken;

/** A storage system for the auth server.
 * 
 * @author gaprice@lbl.gov
 *
 */
public interface AuthStorage {
	
	/** Create a new local account. Note that new accounts are always created
	 * with no roles.
	 * @param local the user to create.
	 * @throws UserExistsException if the user already exists.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void createLocalUser(NewLocalUser local)
			throws AuthStorageException, UserExistsException;

	/** Change a local user's password.
	 * @param name the name of the user.
	 * @param pwdHash the new encrypted password.
	 * @param salt the salt used to encrypt the password.
	 * @param forceReset whether the user should be forced to reset their password on the next
	 * login.
	 * @throws NoSuchUserException if the user doesn't exist or is not a local user.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void changePassword(UserName name, byte[] pwdHash, byte[] salt, boolean forceReset)
			throws NoSuchUserException, AuthStorageException;
	
	/** Force a local user to reset their password on the next login.
	 * @param name the name of the user.
	 * @throws NoSuchUserException if the user doesn't exist or is not a local user.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void forcePasswordReset(UserName name) throws NoSuchUserException, AuthStorageException;
	
	/** Force all local users to reset their passwords on the next login.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void forcePasswordReset() throws AuthStorageException;
	
	/** Create a non-local account. Note that accounts are always created without roles.
	 * @param authUser the user to create.
	 * @throws UserExistsException if the user already exists.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 * @throws IdentityLinkedException if the remote identity provided with the user is already
	 * linked to a different user.
	 */
	void createUser(NewUser authUser)
			throws UserExistsException, AuthStorageException, IdentityLinkedException;
	
	/** Disable a user account.
	 * @param user the name of the account to be disabled.
	 * @param admin the admin disabling the account.
	 * @param reason the reason the account is being disabled.
	 * @throws NoSuchUserException if the user does not exist.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void disableAccount(UserName user, UserName admin, String reason)
			throws NoSuchUserException, AuthStorageException;

	/** Enable a disabled user account.
	 * @param user the name of the account to be enabled.
	 * @param admin the admin enabling the account.
	 * @throws NoSuchUserException if the user does not exist.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void enableAccount(UserName user, UserName admin)
			throws NoSuchUserException, AuthStorageException;
	
	/** Get a local or non-local user.
	 * @param userName the user to get.
	 * @return the user.
	 * @throws NoSuchUserException if the user does not exist.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	AuthUser getUser(UserName userName)
			throws AuthStorageException, NoSuchUserException;
	
	/** Gets a user linked to a remote identity. Returns null if the user doesn't exist. If the 
	 * provider details (provider username, email address, and full name) are different, the
	 * details are updated in the storage system.
	 * @param remoteID a remote identity linked to a user.
	 * @return the user linked to the remote identity or null if there is no such user.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	AuthUser getUser(RemoteIdentity remoteID) throws AuthStorageException;
	
	/** Get the display names for a set of users. Any non-existent users are left out of the
	 * returned map.
	 * @param usernames the usernames for which to get display names.
	 * @return a mapping of username to display name.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	Map<UserName, DisplayName> getUserDisplayNames(Set<UserName> usernames)
			throws AuthStorageException;
	
	/** Search for users based on a prefix of the user and display names and the user's roles.
	 * @param prefix a string prefix with which to search. The prefix matches the start of the
	 * username or the start of any part of the whitespace tokenized display name.
	 * @param searchFields the fields on which the prefix search will be performed. If empty, the
	 * search will proceed on all fields.
	 * @param searchRoles limit the returned users to those with these roles.
	 * @param searchCustomRoles limit the returned users to those with these custom roles.
	 * @param maxReturnedUsers the maximum number of users to return.
	 * @param isRegex true if the prefix is a regex. If the prefix is sourced from user provided
	 * information, be very careful when setting this flag to true.
	 * @return a mapping of user name to display name for the discovered users.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	Map<UserName, DisplayName> getUserDisplayNames(
			String prefix,
			Set<SearchField> searchFields,
			Set<Role> searchRoles,
			Set<String> searchCustomRoles,
			int maxReturnedUsers,
			boolean isRegex)
			throws AuthStorageException;

	/** Get a local user.
	 * @param userName the user to get.
	 * @return a local user.
	 * @throws NoSuchUserException if the local user does not exist.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	LocalUser getLocalUser(UserName userName)
			throws AuthStorageException, NoSuchUserException;
	
	/** Update the display name and/or email address for a user.
	 * @param userName the user to update.
	 * @param update the update to apply.
	 * @throws NoSuchUserException if the user does not exist.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void updateUser(UserName userName, UserUpdate update)
			throws NoSuchUserException, AuthStorageException;
	
	/** Set the last login date for a user.
	 * @param userName the user to modify.
	 * @param lastLogin the last login date for the user.
	 * @throws NoSuchUserException if the user does not exist.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void setLastLogin(UserName userName, Date lastLogin)
			throws NoSuchUserException, AuthStorageException;
	
	/** Store a token in the database. No checking is done on the validity
	 * of the token - passing in tokens with bad data is a programming error.
	 * @param t the token to store.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void storeToken(HashedToken t) throws AuthStorageException;

	/** Get a token from the database based on the hash of the token.
	 * @param token the hashed token from which to retrieve details.
	 * @return the token.
	 * @throws NoSuchTokenException if no token matches the incoming token hash.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	HashedToken getToken(IncomingHashedToken token)
			throws AuthStorageException, NoSuchTokenException;

	/** Get all the tokens for a user.
	 * @param userName the user for which to retrieve tokens.
	 * @return the tokens that the user possesses.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	Set<HashedToken> getTokens(UserName userName) throws AuthStorageException;

	/** Deletes a token from the database.
	 * @param userName the user that owns the token.
	 * @param tokenId the ID of the token.
	 * @throws NoSuchTokenException if the user does not possess a token with the given ID.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void deleteToken(UserName userName, UUID tokenId)
			throws AuthStorageException, NoSuchTokenException;

	/** Deletes all tokens for a user.
	 * @param userName the user whose tokens will be deleted.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void deleteTokens(UserName userName) throws AuthStorageException;
	
	/** Delete all tokens in the database.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void deleteTokens() throws AuthStorageException;

	/** Update roles for a user.
	 * @param userName the user to update.
	 * @param addRoles the roles to add the the user.
	 * @param removeRoles the roles to remove from the user.
	 * @throws NoSuchUserException if the user does not exist.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void updateRoles(UserName userName, Set<Role> addRoles, Set<Role> removeRoles)
			throws AuthStorageException, NoSuchUserException;

	/** Add a custom role if it does not already exist, or modify it if it does.
	 * @param role the role to add or modify.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void setCustomRole(CustomRole role) throws AuthStorageException;
	
	/** Deletes a custom role from the database and removes it from all users.
	 * @param roleId the ID of the role.
	 * @throws NoSuchRoleException if there is no such role.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void deleteCustomRole(String roleId) throws NoSuchRoleException, AuthStorageException;

	/** Get all the custom roles in the database.
	 * @return the custom roles.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	Set<CustomRole> getCustomRoles() throws AuthStorageException;

	/** Updates custom roles for a user.
	 * @param userName the user to modify.
	 * @param addRoles the roles to add to the user.
	 * @param removeRoles the roles to remove from the user. 
	 * @throws NoSuchUserException if the user doesn't exist.
	 * @throws NoSuchRoleException if one or more of the input roles do not exist in the database.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs. 
	 */
	void updateCustomRoles(UserName userName, Set<String> addRoles, Set<String> removeRoles)
			throws NoSuchUserException, AuthStorageException, NoSuchRoleException;

	/** Store a temporary token with a set of remote identities.
	 * @param token the temporary token.
	 * @param ids the set of remote identities.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void storeIdentitiesTemporarily(
			TemporaryHashedToken token,
			Set<RemoteIdentityWithLocalID> ids)
			throws AuthStorageException;

	/** Get a set of identities associated with a token.
	 * @param token the token.
	 * @return the set of identities associated with the token.
	 * @throws NoSuchTokenException if the token does not exist in the storage system.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	Set<RemoteIdentityWithLocalID> getTemporaryIdentities(
			IncomingHashedToken token)
			throws AuthStorageException, NoSuchTokenException;

	/** Link an account to a remote identity.
	 * @param userName the user to which the remote identity will be linked. 
	 * @param remoteID the remote identity.
	 * @throws NoSuchUserException if the user does not exist.
	 * @throws LinkFailedException if the user was a local user or the remote identity is already
	 * linked to another user.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void link(UserName userName, RemoteIdentityWithLocalID remoteID)
			throws NoSuchUserException, AuthStorageException,
			LinkFailedException;

	/** Remove a remote identity from a user.
	 * @param userName the user.
	 * @param id the remote identity to remove from the user.
	 * @throws UnLinkFailedException if the user doesn't exist, the user only has one identity,
	 * or the user does not possess the specified identity.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	void unlink(UserName userName, UUID id)
			throws AuthStorageException, UnLinkFailedException;

	/** Update the system configuration.
	 * @param authConfigSet the configuration to set. Null values are ignored.
	 * @param overwrite whether the new configuration should overwrite the current configuration.
	 * If false, only new values are stored.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	<T extends ExternalConfig> void updateConfig(
			AuthConfigSet<T> authConfigSet,
			boolean overwrite)
			throws AuthStorageException;

	/** Get the system configuration.
	 * @param mapper a mapper to transform a map of the external config into an external config
	 * class.
	 * @return the sysetem configuration.
	 * @throws ExternalConfigMappingException if the mapper failed to transform the external config
	 * map into the external config class.
	 * @throws AuthStorageException if a problem connecting with the storage
	 * system occurs.
	 */
	<T extends ExternalConfig> AuthConfigSet<T> getConfig(
			ExternalConfigMapper<T> mapper)
			throws AuthStorageException, ExternalConfigMappingException;
}
