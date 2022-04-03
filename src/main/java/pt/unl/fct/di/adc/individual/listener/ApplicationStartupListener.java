package pt.unl.fct.di.adc.individual.listener;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

import org.apache.commons.codec.digest.DigestUtils;

import com.google.cloud.Timestamp;
import com.google.cloud.datastore.*;

@WebListener
public class ApplicationStartupListener implements ServletContextListener{
	
	private final Datastore datastore = DatastoreOptions.getDefaultInstance().getService();

	@Override
	public void contextInitialized(ServletContextEvent sce) {
		Transaction txn = datastore.newTransaction();
		
		try {
			
			Key userKey = datastore.newKeyFactory().setKind("User").newKey("admin");
			
			Entity entity = txn.get(userKey);
			
			if(entity == null) {
				Entity admin = Entity.newBuilder(userKey)
						  .set("user_pwd", DigestUtils.sha512Hex("admin"))
						  .set("user_email", "admin@admin.com")
						  .set("user_name", "admin")
						  .set("user_register_date", Timestamp.now())
						  .set("user_register_ip", "")
						  .set("user_privacy", false)
						  .set("user_phone", "")
						  .set("user_mobile", "")
						  .set("user_addr", StringValue.newBuilder("").setExcludeFromIndexes(true).build())
						  .set("user_city", StringValue.newBuilder("").setExcludeFromIndexes(true).build())
						  .set("user_cp", StringValue.newBuilder("").setExcludeFromIndexes(true).build())
						  .set("user_nif", StringValue.newBuilder("").setExcludeFromIndexes(true).build())
						  .set("user_acc_state", true)
						  .set("user_role", "SU")
						  .build();
				
				txn.put(admin);
				txn.commit();
				return;
			} else
				return;
		} finally {
			if(txn.isActive())
				txn.rollback();
		}
	}

	@Override
	public void contextDestroyed(ServletContextEvent sce) {
		return;
	}

}
