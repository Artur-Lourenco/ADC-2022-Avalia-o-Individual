package pt.unl.fct.di.adc.individual.util;

import java.util.UUID;

public class AuthToken {
	
	private String username;
	private String tokenID;
	private long creationDate;
	private long expirationDate;
	private String role;
	
	public static final long EXPIRATION_TIME = 1000*60*10; //10m
	
	public AuthToken() {
		
	}
	
	public AuthToken(String username, String role) {
		this.username = username;
		this.tokenID = UUID.randomUUID().toString();
		this.creationDate = System.currentTimeMillis();
		this.expirationDate = this.creationDate + EXPIRATION_TIME;
		this.role = role;
	}
	
	public String getUsername() {
		return this.username;
	}
	
	public String getTokenID() {
		return this.tokenID;
	}
	
	public long getCreationDate() {
		return this.creationDate;
	}
	
	public long getExpirationDate() {
		return this.expirationDate;
	}
	
	public String getRole() {
		return this.role;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public void setTokenID(String tokenID) {
		this.tokenID = tokenID;
	}
	
	public void setCreationDate(long creationDate) {
		this.creationDate = creationDate;
	}
	
	public void setExpirationDate(long expirationDate) {
		this.expirationDate = expirationDate;
	}
	
	public void setRole(String role) {
		this.role = role;
	}

}
