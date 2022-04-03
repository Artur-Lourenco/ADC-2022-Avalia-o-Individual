package pt.unl.fct.di.adc.individual.resources;

import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;

import pt.unl.fct.di.adc.individual.util.RegisterData;

@Path("/register")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class RegisterResource {

	/**
	 * A Logger object
	 */
	private static final Logger LOG = Logger.getLogger(RegisterResource.class.getName());

	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	public RegisterResource() {
		// Nothing to be done here
	}

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doRegister(RegisterData data, 
							   @Context HttpServletRequest request,
							   @QueryParam("profile") @DefaultValue("false") boolean profile,
							   @DefaultValue("") @QueryParam("phoneNr") String phoneNr,
							   @QueryParam("mobileNr") @DefaultValue("") String mobileNr,
							   @QueryParam("mainAddr") @DefaultValue("") String mainAddr,
							   @QueryParam("city") @DefaultValue("") String city,
							   @QueryParam("cp") @DefaultValue("") String cp,
							   @QueryParam("nif") @DefaultValue("") String nif) {
		LOG.fine("Attempting to register user: " + data.getUsername());
		
		//Checks input data
		if(!data.validRegistration())
			return Response.status(Status.BAD_REQUEST).entity("Missing or wrong parameters.").build();
		
		Transaction txn = datastore.newTransaction();
		
		try {
		
			Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.getUsername());
			
			Entity entity = txn.get(userKey);
			
			if(entity != null) {
				
				txn.rollback();
				return Response.status(Status.CONFLICT).entity("Username or password already exists").build();
				
			}
			
			if (!data.checkPasswordValidity(data.getPassword())) {
				
				txn.rollback();
				return Response.status(Status.BAD_REQUEST)
						.entity("Password doesn't match criteria.\n"
								+ "Password should be between 5 to 12 characters and include at least one upper case "
								+ "character, one lower case character, one digit and one special character")
						.build();
				
			}
			
			String hashedPw = DigestUtils.sha512Hex(data.getPassword());
			String hashedConfirmPwd = DigestUtils.sha512Hex(data.getConfirmPwd());
			
			if (!hashedPw.equals(hashedConfirmPwd)) {

				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity("Passwords don't match").build();

			}
			
			if (!data.checkEmailValidity(data.getEmail())) {

				txn.rollback();
				return Response.status(Status.BAD_REQUEST)
						.entity("Invalid email. Email should be of format " + "<string>@<string>. .... .<dom>").build();

			}
			
			if (!data.checkPhoneNrValidity(phoneNr)) {
				
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(
						"Phone number must be portuguese and be between 21******* and 29******* (with 9 digits).").build();
				
			}
			
			if (!data.checkMobileNrValidity(mobileNr)) {

				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(
						"Mobile number must be portuguese: Start with 91,92,93 or 96 and have 9 digits.")
						.build();

			}
			
			if (!data.checkCPValidity(cp)) {
				
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(
						"Postal code must be of format XXXX-XXX with X being digits.")
						.build();
				
			}
			
			if (!data.checkNIFValidity(nif)) {
				
				txn.rollback();
				return Response.status(Status.BAD_REQUEST).entity(
						"NIF must be 9 digits.")
						.build();
				
			}
			
			Entity user = Entity.newBuilder(userKey)
						  .set("user_pwd", hashedPw)
						  .set("user_email", data.getEmail())
						  .set("user_name", data.getName())
						  .set("user_register_date", Timestamp.now())
						  .set("user_register_ip", request.getRemoteAddr())
						  .set("user_privacy", profile)
						  .set("user_phone", phoneNr)
						  .set("user_mobile", mobileNr)
						  .set("user_addr", StringValue.newBuilder(mainAddr).setExcludeFromIndexes(true).build())
						  .set("user_city", StringValue.newBuilder(city).setExcludeFromIndexes(true).build())
						  .set("user_cp", StringValue.newBuilder(cp).setExcludeFromIndexes(true).build())
						  .set("user_nif", StringValue.newBuilder(nif).setExcludeFromIndexes(true).build())
						  .set("user_acc_state", false)
						  .set("user_role", "USER")
						  .build();
			
			txn.put(user);
			txn.commit();
			LOG.info("User " + data.getUsername() + " successfully registered");
			return Response.ok().build();
			
		} finally {
			
			if(txn.isActive())
				txn.rollback();
			
		}
		
	}

}
