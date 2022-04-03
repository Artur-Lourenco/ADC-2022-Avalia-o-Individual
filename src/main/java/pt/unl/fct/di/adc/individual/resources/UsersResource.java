package pt.unl.fct.di.adc.individual.resources;

import java.text.DateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.datastore.*;
import com.google.cloud.datastore.StructuredQuery.CompositeFilter;
import com.google.cloud.datastore.StructuredQuery.PropertyFilter;
import com.google.gson.Gson;

import pt.unl.fct.di.adc.individual.util.PasswordUpdate;
import pt.unl.fct.di.adc.individual.util.RegisterData;

@Path("/{username}")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class UsersResource {
	
	/**
	 * A Logger object
	 */
	private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());

	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();
	
	private final Gson g = new Gson();
	
	public UsersResource() {
		//Nothing to be done here
	}
	
	@PUT
	@Path("/activation")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeActivation(@PathParam("username") String username, 
									@QueryParam("userId") @DefaultValue("") String userId) {
		LOG.fine("Attempting to change activation state");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		Key activatorKey = datastore.newKeyFactory().setKind("User").newKey(userId);
		
		Transaction txn = datastore.newTransaction();
		
		try {
			
			if(userId.equals("")) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("No user to validate").build();
			}
			
			Entity entity = txn.get(userKey);
			
			if(entity == null || entity.getBoolean("user_acc_state") == false) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User does not exist or is inactive").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			Entity userToUpdate = txn.get(activatorKey);
			
			if(userToUpdate == null) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("Target user does not exist").build();
			}
			
			String originalRole = entity.getString("user_role");
			String activatorRole = userToUpdate.getString("user_role");
			
			if( (originalRole.equals("USER") && !username.equals(userId)) || (originalRole.equals("GBO") && !activatorRole.equals("USER")) ||
					(originalRole.equals("GS") && (activatorRole.equals("SU") || activatorRole.equals("GS"))) ) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User doesn't have permission to change account states").build();
			} 
			
			boolean result;
			if(userToUpdate.getBoolean("user_acc_state") == false)
				result = true;
			else
				result = false;
			
			Entity updatedUser = Entity.newBuilder(activatorKey)
								  .set("user_pwd", userToUpdate.getString("user_pwd"))
								  .set("user_email", userToUpdate.getString("user_email"))
								  .set("user_name", userToUpdate.getString("user_name"))
								  .set("user_register_date", userToUpdate.getTimestamp("user_register_date"))
								  .set("user_register_ip", userToUpdate.getString("user_register_ip"))
								  .set("user_privacy", userToUpdate.getBoolean("user_privacy"))
								  .set("user_phone", userToUpdate.getString("user_phone"))
								  .set("user_mobile", userToUpdate.getString("user_mobile"))
								  .set("user_addr", StringValue.newBuilder(userToUpdate.getString("user_addr")).setExcludeFromIndexes(true).build())
								  .set("user_city", StringValue.newBuilder(userToUpdate.getString("user_city")).setExcludeFromIndexes(true).build())
								  .set("user_cp", StringValue.newBuilder(userToUpdate.getString("user_cp")).setExcludeFromIndexes(true).build())
								  .set("user_nif", StringValue.newBuilder(userToUpdate.getString("user_nif")).setExcludeFromIndexes(true).build())
								  .set("user_acc_state", result)
								  .set("user_role", userToUpdate.getString("user_role"))
								  .build();
			
			txn.put(updatedUser);
			txn.commit();
			return Response.ok().entity("Activation state of account changed successfully").build();
			
			
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@PUT
	@Path("/role")
	@Consumes(MediaType.APPLICATION_JSON)
	public Response changeRole(@PathParam("username") String username, 
									@QueryParam("userId") String userId,
									@QueryParam("role") String role) {
		LOG.fine("Attempting to change role");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		//Roles should always be changed by a higher role.
		if(username.equals(userId))
			return Response.status(Status.CONFLICT).entity("User can't change own role").build();
		
		Key roleChangeKey = datastore.newKeyFactory().setKind("User").newKey(userId);
		
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Entity entity = txn.get(userKey);
			
			if(entity == null || entity.getBoolean("user_acc_state") == false) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User does not exist or is inactive").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			Entity userToUpdate = txn.get(roleChangeKey);
			
			if(userToUpdate == null) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User you're trying to change role does not exist").build();
			}
			
			String originalRole = entity.getString("user_role");
			String activatorRole = userToUpdate.getString("user_role");
			
			if(!(role.equals("USER") || role.equals("GBO") || role.equals("GS") || role.equals("SU"))) {
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("Invalid role to assign").build();
			}
			
			if(originalRole.equals("USER") || 
			   originalRole.equals("GBO") ||
			  (originalRole.equals("GS") && !(activatorRole.equals("USER") && role.equals("GBO") ||
					  						  activatorRole.equals("GBO") && role.equals("USER")))) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User doesn't have permission to change account's role").build();
			} 
			
			Entity updatedUser = Entity.newBuilder(roleChangeKey)
								  .set("user_pwd", userToUpdate.getString("user_pwd"))
								  .set("user_email", userToUpdate.getString("user_email"))
								  .set("user_name", userToUpdate.getString("user_name"))
								  .set("user_register_date", userToUpdate.getTimestamp("user_register_date"))
								  .set("user_register_ip", userToUpdate.getString("user_register_ip"))
								  .set("user_privacy", userToUpdate.getBoolean("user_privacy"))
								  .set("user_phone", userToUpdate.getString("user_phone"))
								  .set("user_mobile", userToUpdate.getString("user_mobile"))
								  .set("user_addr", StringValue.newBuilder(userToUpdate.getString("user_addr")).setExcludeFromIndexes(true).build())
								  .set("user_city", StringValue.newBuilder(userToUpdate.getString("user_city")).setExcludeFromIndexes(true).build())
								  .set("user_cp", StringValue.newBuilder(userToUpdate.getString("user_cp")).setExcludeFromIndexes(true).build())
								  .set("user_nif", StringValue.newBuilder(userToUpdate.getString("user_nif")).setExcludeFromIndexes(true).build())
								  .set("user_acc_state", userToUpdate.getBoolean("user_acc_state"))
								  .set("user_role", role)
								  .build();
			
			//Checks if updated user has token, if he does delete it, so he has to re-login so info updates.
			Key updatedTokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", userId))
					.setKind("UserToken").newKey("token");
			
			Entity tokenToDelete = txn.get(updatedTokenKey);
			
			if(tokenToDelete != null)
				txn.delete(updatedTokenKey);
			
			txn.put(updatedUser);
			txn.commit();
			return Response.ok().entity("Role of account changed successfully").build();
			
			
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@DELETE
	public Response doDelete(@PathParam("username") String username, @QueryParam("userId") String userId) {
		LOG.fine("Attempting to delete user");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		Transaction txn = datastore.newTransaction();
		
		String deletionId = "";
		
		try {
			
			Entity entity = txn.get(userKey);
			
			if(entity == null) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User doesn't exist.").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			if(userId != null && !username.equals(userId)) {//Deletion of another user
				Key deletionKey = datastore.newKeyFactory().setKind("User").newKey(userId);
				
				Entity userToDelete = txn.get(deletionKey);
				
				if(userToDelete == null) {
					txn.rollback();
					return Response.status(Status.NOT_FOUND).entity("User you're trying to delete does not exist").build();
				}
				
				String originalRole = entity.getString("user_role");
				String activatorRole = userToDelete.getString("user_role");
				
				if( originalRole.equals("USER") || 
				   (originalRole.equals("GBO") && !activatorRole.equals("USER")) ||
				   (originalRole.equals("GS") && (activatorRole.equals("SU") || activatorRole.equals("GS"))) ) {
					txn.rollback();
					return Response.status(Status.FORBIDDEN).entity("User doesn't have permission to delete this account").build();
				} 
				
				deletionId = userId;
				
				txn.delete(deletionKey);
			} else {
				deletionId = username;
				
				txn.delete(userKey);
			}
			
			//Checks if updated user has token, if he does delete it, so he has to re-login so info updates.
			Key updatedTokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", deletionId))
					.setKind("UserToken").newKey("token");
			
			Entity tokenToDelete = txn.get(updatedTokenKey);
			
			if(tokenToDelete != null)
				txn.delete(updatedTokenKey);
			
			txn.commit();
			return Response.ok().entity("User deleted successfully").build();
			
			
		} catch (Exception e) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if(txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}
	
	@GET
	@Path("/list")
	public Response listUsers(@PathParam("username") String username) {
		LOG.fine("Attempting to list users");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Entity user = txn.get(userKey);
			
			if(user == null || user.getBoolean("user_acc_state") == false) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User doesn't exist or is inactive.").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			Query<Entity> query;

			String userRole = user.getString("user_role");
			
			List<String> list = new ArrayList<String>();
			
			if(userRole.equals("USER")) {
				query = Query.newEntityQueryBuilder().setKind("User").setFilter(
						CompositeFilter.and(PropertyFilter.eq("user_role","USER"), 
											PropertyFilter.eq("user_acc_state",true),
											PropertyFilter.eq("user_privacy",true))).build();
				
				QueryResults<Entity> userQ = txn.run(query);
				
				userQ.forEachRemaining(userList -> {
					list.add("username - " + userList.getKey().getName());
					list.add("email - " + userList.getString("user_email"));
					list.add("name - " + userList.getString("user_name"));
				});
			} else { 
				if(userRole.equals("GBO")) {
				query = Query.newEntityQueryBuilder().setKind("User").setFilter(
						PropertyFilter.eq("user_role","USER")).build();
				} else if(userRole.equals("GS")) {
					query = Query.newEntityQueryBuilder().setKind("User").setFilter(
							CompositeFilter.and(PropertyFilter.eq("user_role","USER"),
												PropertyFilter.eq("user_role","GBO"))).build();
				} else {
					query = Query.newEntityQueryBuilder().setKind("User").build();
				}
			
				QueryResults<Entity> userQ = txn.run(query);
				
				userQ.forEachRemaining(userList -> {
					list.add("username - " + userList.getKey().getName());
					list.add("email - " + userList.getString("user_email"));
					list.add("name - " + userList.getString("user_name"));
					list.add("register date - " + userList.getTimestamp("user_register_date"));
					list.add("register ip - " + userList.getString("user_register_ip"));
					list.add("phone number - " + userList.getString("user_phone"));
					list.add("mobile number - " + userList.getString("user_mobile"));
					list.add("address - " + userList.getString("user_addr"));
					list.add("city - " + userList.getString("user_city"));
					list.add("cp - " + userList.getString("user_cp"));
					list.add("nif - " + userList.getString("user_nif"));
					list.add("role - " + userList.getString("user_role"));
				});
			
			}
			
			txn.commit();
			return Response.ok(g.toJson(list)).build();
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@GET
	@Path("/token")
	public Response getToken(@PathParam("username") String username) {
		LOG.fine("Attempting to show session token");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Entity user = txn.get(userKey);
			
			if(user == null || user.getBoolean("user_acc_state") == false) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User doesn't exist or is inactive.").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			List<String> tokenInfo = new ArrayList<String>();
			tokenInfo.add("Username - " + token.getKey().getName());
			tokenInfo.add("Token Id - " + token.getString("token_user_id"));
			tokenInfo.add("Creation date - " + DateFormat.getInstance().format(token.getLong("token_creation_date")).toString());
			tokenInfo.add("Expiration date - " + DateFormat.getInstance().format(token.getLong("token_expiration_date")).toString());
			tokenInfo.add("User role - " + token.getString("token_role"));
			
			txn.commit();
			return Response.ok(g.toJson(tokenInfo)).build();
			
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@DELETE
	@Path("/logout")
	public Response doLogout(@PathParam("username") String username) {
		LOG.fine("Attempting to logout");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		Transaction txn = datastore.newTransaction();
		
		try {
			Entity user = txn.get(userKey);
			
			if(user == null || user.getBoolean("user_acc_state") == false) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User doesn't exist or is inactive.").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			txn.delete(tokenKey);
			txn.commit();
			return Response.ok().entity("Logged out successfully").build();
			
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@PUT
	@Path("/update/password")
	public Response updatePassword(@PathParam("username") String username, PasswordUpdate data) {
		LOG.fine("Attempting to update password");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Entity user = txn.get(userKey);
			
			if(user == null || user.getBoolean("user_acc_state") == false) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User doesn't exist or is inactive.").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			String userPwd = user.getString("user_pwd");
			
			if(!userPwd.equals(DigestUtils.sha512Hex(data.getOldPwd()))) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("Password doesn't match old password").build();
			}
			
			if (!data.checkPasswordValidity(data.getPassword())) {
				
				txn.rollback();
				return Response.status(Status.BAD_REQUEST)
						.entity("Password doesn't match criteria.\n"
								+ "Password should be between 5 to 12 characters and include at least one upper case "
								+ "character, one lower case character, one digit and one special character")
						.build();
				
			}
			
			String newPwd = DigestUtils.sha512Hex(data.getPassword());
			String confirmNewPwd = DigestUtils.sha512Hex(data.getConfirmPwd());
			
			if(!newPwd.equals(confirmNewPwd)) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("Passwords don't match").build();
			}
			
			Entity updatedUser = Entity.newBuilder(userKey)
					  .set("user_pwd", newPwd)
					  .set("user_email", user.getString("user_email"))
					  .set("user_name", user.getString("user_name"))
					  .set("user_register_date", user.getTimestamp("user_register_date"))
					  .set("user_register_ip", user.getString("user_register_ip"))
					  .set("user_privacy", user.getBoolean("user_privacy"))
					  .set("user_phone", user.getString("user_phone"))
					  .set("user_mobile", user.getString("user_mobile"))
					  .set("user_addr", StringValue.newBuilder(user.getString("user_addr")).setExcludeFromIndexes(true).build())
					  .set("user_city", StringValue.newBuilder(user.getString("user_city")).setExcludeFromIndexes(true).build())
					  .set("user_cp", StringValue.newBuilder(user.getString("user_cp")).setExcludeFromIndexes(true).build())
					  .set("user_nif", StringValue.newBuilder(user.getString("user_nif")).setExcludeFromIndexes(true).build())
					  .set("user_acc_state", user.getBoolean("user_acc_state"))
					  .set("user_role", user.getString("user_role"))
					  .build();
			
			txn.put(updatedUser);
			txn.commit();
			
			return Response.ok().entity("Password updated successfully").build();
			
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}
	
	@PUT
	@Path("/update/user")
	public Response updateUser(@PathParam("username") String username, RegisterData data, 
			   @QueryParam("profile") @DefaultValue("false") boolean profile,
			   @DefaultValue("") @QueryParam("phoneNr") String phoneNr,
			   @QueryParam("mobileNr") @DefaultValue("") String mobileNr,
			   @QueryParam("mainAddr") @DefaultValue("") String mainAddr,
			   @QueryParam("city") @DefaultValue("") String city,
			   @QueryParam("cp") @DefaultValue("") String cp,
			   @QueryParam("nif") @DefaultValue("") String nif) {
		LOG.fine("Attempting to update user");
		
		Key userKey = datastore.newKeyFactory().setKind("User").newKey(username);
		
		Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", username))
				.setKind("UserToken").newKey("token");
		
		Transaction txn = datastore.newTransaction();
		
		try {
			Entity user = txn.get(userKey);
			
			if(user == null || user.getBoolean("user_acc_state") == false) {
				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User doesn't exist or is inactive.").build();
			}
			
			Entity token = txn.get(tokenKey);
			
			if(token == null || Long.valueOf(token.getLong("token_expiration_date")).compareTo((long)System.currentTimeMillis())<0) {
				txn.rollback();
				return Response.status(Status.UNAUTHORIZED).entity("User session has expired").build();
			}
			
			Key updateKey;
			
			Entity userToUpdate;
			
			if(username.equals(data.getUsername())) {
				updateKey = userKey;
				userToUpdate = user;
			} else {
				updateKey = datastore.newKeyFactory().setKind("User").newKey(data.getUsername());
				userToUpdate = txn.get(updateKey);
			}
			
			String userRole = user.getString("user_role");
			String updateRole = userToUpdate.getString("user_role");
			
			if(userRole.equals("USER") && !username.equals(data.getUsername())) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User with this role can only update own account").build();
			}
			
			if( (userRole.equals("GBO") && !updateRole.equals("USER")) ||
				 userRole.equals("GS") && (updateRole.equals("GS") || updateRole.equals("SU"))) {
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("User doesn't have permision to update this account").build();
			}
			
			boolean privacy = userToUpdate.getBoolean("user_privacy");
			if(privacy != profile)
				privacy = !privacy;
			String phone = userToUpdate.getString("user_phone");
			if(phone.equals("") || (!phoneNr.equals("") && !phoneNr.equals(phone)))
				phone = phoneNr;
			String mobile = userToUpdate.getString("user_mobile");
			if(mobile.equals("") || (!mobileNr.equals("") && !mobileNr.equals(mobile)))
				mobile = mobileNr;
			String addr = userToUpdate.getString("user_addr");
			if(addr.equals("") || (!mainAddr.equals("") && !mainAddr.equals(addr)))
				addr = mainAddr;
			String userCity = userToUpdate.getString("user_city");
			if(userCity.equals("") || (!city.equals("") && !city.equals(userCity)))
				userCity = city;
			String userCp = userToUpdate.getString("user_cp");
			if(userCp.equals("") || (!cp.equals("") && !cp.equals(userCp)))
				userCp = cp;
			String userNif = userToUpdate.getString("user_nif");
			if(userNif.equals("") || (!nif.equals("") && !nif.equals(userNif)))
				userNif = nif;
			
			Entity updatedUser;
			
			if(userRole.equals("USER")) {
				updatedUser = Entity.newBuilder(updateKey)
						  .set("user_pwd", userToUpdate.getString("user_pwd"))
						  .set("user_email", userToUpdate.getString("user_email"))
						  .set("user_name", userToUpdate.getString("user_name"))
						  .set("user_register_date", userToUpdate.getTimestamp("user_register_date"))
						  .set("user_register_ip", userToUpdate.getString("user_register_ip"))
						  .set("user_privacy", profile)
						  .set("user_phone", phone)
						  .set("user_mobile", mobile)
						  .set("user_addr", addr)
						  .set("user_city", userCity)
						  .set("user_cp", userCp)
						  .set("user_nif", userNif)
						  .set("user_acc_state", userToUpdate.getBoolean("user_acc_state"))
						  .set("user_role", userToUpdate.getString("user_role"))
						  .build();
			} else {
				String email = userToUpdate.getString("user_email");
				if(data.getEmail() != null && !email.equals(data.getEmail()))
					email = data.getEmail();
				String name = userToUpdate.getString("user_name");
				if(data.getName() != null && !name.equals(data.getName()))
					name = data.getName();
				
				updatedUser = Entity.newBuilder(updateKey)
						  .set("user_pwd", userToUpdate.getString("user_pwd"))
						  .set("user_email", email)
						  .set("user_name", name)
						  .set("user_register_date", userToUpdate.getTimestamp("user_register_date"))
						  .set("user_register_ip", userToUpdate.getString("user_register_ip"))
						  .set("user_privacy", profile)
						  .set("user_phone", phone)
						  .set("user_mobile", mobile)
						  .set("user_addr", addr)
						  .set("user_city", userCity)
						  .set("user_cp", userCp)
						  .set("user_nif", userNif)
						  .set("user_acc_state", userToUpdate.getBoolean("user_acc_state"))
						  .set("user_role", userToUpdate.getString("user_role"))
						  .build();
			}
			
			txn.put(updatedUser);
			txn.commit();
			return Response.ok().entity("Updated user successfully").build();
			
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
		
	}
	
}
