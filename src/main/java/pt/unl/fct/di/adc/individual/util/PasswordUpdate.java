package pt.unl.fct.di.adc.individual.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordUpdate {
	
	private String oldPwd;
	private String password;
	private String confirmPwd;
	
	public PasswordUpdate() {
	}
	
	public PasswordUpdate(String oldPwd, String password, String confirmPwd) {
		this.oldPwd = oldPwd;
		this.password = password;
		this.confirmPwd = confirmPwd;
	}
	
	public String getOldPwd() {
		return this.oldPwd;
	}
	
	public String getPassword() {
		return this.password;
	}
	
	public String getConfirmPwd() {
		return this.confirmPwd;
	}
	
	public void setOldPwd(String oldPwd) {
		this.oldPwd = oldPwd;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
	
	public void setConfirmPwd(String confirmPwd) {
		this.confirmPwd = confirmPwd;
	}
	
	public boolean checkPasswordValidity(String password) {
		String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[-+_!@#$%^&*., ?]).+$";
		
		Pattern p = Pattern.compile(regex);
		
		if(password.length() < 5 || password.length() > 12 || password.contains(" "))
			return false;
		
		Matcher m = p.matcher(password);
		
		return m.matches();
	}

}
