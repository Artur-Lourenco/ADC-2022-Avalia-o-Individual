package pt.unl.fct.di.adc.individual.util;

public class LoginData {
	
	private String username;
	private String password;
	
	public LoginData() { 
		
	}
	
	public LoginData(String username, String password) {
		this.username = username;
		this.password = password;
	}
	
	public String getUsername() {
		return this.username;
	}
	
	public String getPassword() {
		return this.password;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}

}
