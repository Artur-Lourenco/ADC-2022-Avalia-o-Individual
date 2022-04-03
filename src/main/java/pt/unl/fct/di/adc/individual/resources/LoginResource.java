package pt.unl.fct.di.adc.individual.resources;

import java.util.logging.Logger;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.datastore.Datastore;
import com.google.cloud.datastore.DatastoreOptions;
import com.google.cloud.datastore.Entity;
import com.google.cloud.datastore.Key;
import com.google.cloud.datastore.PathElement;
import com.google.cloud.datastore.Transaction;
import com.google.gson.Gson;

import pt.unl.fct.di.adc.individual.util.AuthToken;
import pt.unl.fct.di.adc.individual.util.LoginData;

@Path("/login")
@Produces(MediaType.APPLICATION_JSON + ";charset=utf-8")
public class LoginResource {

	/**
	 * A Logger object
	 */
	private static final Logger LOG = Logger.getLogger(LoginResource.class.getName());
	
	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	private final Gson g = new Gson();

	public LoginResource() {
	} // Nothing to be done here (could be omitted)

	@POST
	@Consumes(MediaType.APPLICATION_JSON)
	public Response doLogin(LoginData data) {
		LOG.fine("Login attempt by user: " + data.getUsername());

		Key userKey = datastore.newKeyFactory().setKind("User").newKey(data.getUsername());

		Transaction txn = datastore.newTransaction();

		try {

			Entity user = txn.get(userKey);
			if (user == null) {

				txn.rollback();
				return Response.status(Status.NOT_FOUND).entity("User or password doesn't exist").build();

			}

			boolean isActive = user.getBoolean("user_acc_state");
			
			if(!isActive) {
				
				txn.rollback();
				return Response.status(Status.FORBIDDEN).entity("Account is not activated").build();
				
			}

			String hashedPwd = (String) user.getString("user_pwd");

			if (hashedPwd.equals(DigestUtils.sha512Hex(data.getPassword()))) {

				AuthToken token = new AuthToken(data.getUsername(), user.getString("user_role"));

				Key tokenKey = datastore.newKeyFactory().addAncestors(PathElement.of("User", data.getUsername()))
						.setKind("UserToken").newKey("token");

				Entity tokenEntity = Entity.newBuilder(tokenKey)
						.set("token_role", user.getString("user_role"))
						.set("token_user_id", token.getTokenID())
						.set("token_creation_date", token.getCreationDate())
						.set("token_expiration_date", token.getExpirationDate())
						.build();

				txn.put(tokenEntity);
				txn.commit();

				LOG.info("User " + data.getUsername() + " logged in successfully.");
				return Response.ok(g.toJson(token)).build();
			} else {
				return Response.status(Status.FORBIDDEN).entity("User or password doesn't exist.").build();
			}
		} catch (Exception e) {
			txn.rollback();
			LOG.severe(e.getMessage());
			return Response.status(Status.INTERNAL_SERVER_ERROR).build();
		} finally {
			if (txn.isActive()) {
				txn.rollback();
				return Response.status(Status.INTERNAL_SERVER_ERROR).build();
			}
		}
	}

}
