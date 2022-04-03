package pt.unl.fct.di.adc.individual.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.cloud.Timestamp;

public class RegisterData {
	
	private String username;
	private String password;
	private String confirmationPwd;
	private String email;
	private String name;
	private Timestamp creationDate;
	private boolean isProfilePublic;
	private String phoneNr;
	private String mobileNr;
	private String mainAddr;
	private String city;
	private String cp;
	private String nif;
	private String role;
	private boolean isActive;
	
	public RegisterData() { 
		
	}
	
	public RegisterData(String username, String password, String confirmationPwd, 
						String email, String name) {
		this.username = username;
		this.password = password;
		this.confirmationPwd = confirmationPwd;
		this.email =  email;
		this.name = name;
		role = "USER";
		isActive = false;
	}
	
	public String getUsername() {
		return this.username;
	}
	
	public String getPassword() {
		return this.password;
	}
	
	public String getConfirmPwd() {
		return this.confirmationPwd;
	}
	
	public Timestamp getCreationDate() {
		return this.creationDate;
	}
	
	public String getEmail() {
		return this.email;
	}
	
	public String getName() {
		return this.name;
	}
	
	public boolean getProfilePrivacy() {
		return this.isProfilePublic;
	}
	
	public String getPhoneNr() {
		return this.phoneNr;
	}
	
	public String getMobileNr() {
		return this.mobileNr;
	}
	
	public String getMainAddr() {
		return this.mainAddr;
	}
	
	public String getCity() {
		return this.city;
	}
	
	public String getCP() {
		return this.cp;
	}
	
	public String getNIF() {
		return this.nif;
	}
	
	public String getRole() {
		return this.role;
	}
	
	public boolean getAccState() {
		return this.isActive;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
	
	public void setConfirmPwd(String confirmationPwd) {
		this.confirmationPwd = confirmationPwd;
	}
	
	public void setCreationDate(Timestamp creationDate) {
		this.creationDate = creationDate;
	}
	
	public void setEmail(String email) {
		this.email = email;
	}
	
	public void setName(String name) {
		this.name = name;
	}
	
	public void setProfilePrivacy(boolean isProfilePublic) {
		this.isProfilePublic = isProfilePublic;
	}
	
	public void setPhoneNr(String phoneNr) {
		this.phoneNr = phoneNr;
	}
	
	public void setMobileNr(String mobileNr) {
		this.mobileNr = mobileNr;
	}
	
	public void setMainAddr(String mainAddr) {
		this.mainAddr = mainAddr;
	}
	
	public void setCity(String city) {
		this.city = city;
	}
	
	public void setCP(String cp) {
		this.cp = cp;
	}
	
	public void setNIF(String nif) {
		this.nif = nif;
	}
	
	public void setRole(String role) {
		this.role = role;
	}
	
	public void setAccState(boolean isActive) {
		this.isActive = isActive;
	}
	
	public boolean checkPasswordValidity(String password) {
		String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[-+_!@#$%^&*., ?]).+$";
		
		Pattern p = Pattern.compile(regex);
		
		if(password.length() < 5 || password.length() > 12 || password.contains(" "))
			return false;
		
		Matcher m = p.matcher(password);
		
		return m.matches();
	}
	
	public boolean checkEmailValidity(String email) {
		String regex = "^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$";
		
		Pattern p = Pattern.compile(regex);
		
		Matcher m = p.matcher(email);
		
		return m.matches();
	}
	
	public boolean checkPhoneNrValidity(String phoneNr) {
		//String is empty in case user didn't insert it, which returns true since it's optional
		if(phoneNr.equals(""))
			return true;
		
		//Checks for portuguese phone numbers.
		String regex = "^[2][1-9]+[0-9]{7}$";
		
		Pattern p = Pattern.compile(regex);
		
		Matcher m = p.matcher(phoneNr);
		
		return m.matches();
	}
	
	public boolean checkMobileNrValidity(String mobileNr) {
		// String is empty in case user didn't insert it, which returns true since it's
		// optional
		if (mobileNr.equals(""))
			return true;

		// Checks for portuguese mobile numbers.
		String regex = "^[9][1236]+[0-9]{7}$";

		Pattern p = Pattern.compile(regex);

		Matcher m = p.matcher(mobileNr);

		return m.matches();
	}
	
	public boolean checkCPValidity(String cp) {
		// String is empty in case user didn't insert it, which returns true since it's
		// optional
		if (cp.equals(""))
			return true;
		
		//Just checks for the format dddd-ddd with d being a digit
		String regex = "^[0-9]{4}+[-]+[0-9]{3}$";
		
		Pattern p = Pattern.compile(regex);
		
		Matcher m = p.matcher(cp);
		
		return m.matches();
	}
	
	public boolean checkNIFValidity(String nif) {
		// String is empty in case user didn't insert it, which returns true since it's
		// optional
		if (nif.equals(""))
			return true;
		
		//Checks if has 9 digits and is all numbers
		String regex ="[0-9]{9}";
		
		Pattern p = Pattern.compile(regex);
		
		Matcher m = p.matcher(nif);
		
		return m.matches();
	}
	
	public boolean validRegistration() {
		if(this.username == null || this.password == null || this.email == null || this.name == null || this.confirmationPwd == null)
			return false;
		if(this.username.equals("") || this.password.equals("") || this.email.equals("") || this.name.equals(""))
			return false;
		return true;
	}

}
