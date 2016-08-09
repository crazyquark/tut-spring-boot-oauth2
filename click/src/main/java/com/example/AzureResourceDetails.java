package com.example;


import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

public class AzureResourceDetails extends AuthorizationCodeResourceDetails {
	private String responseType = "code id_token";
	private String responseMode = "form_post";
	private String resource;

	public AzureResourceDetails(AuthorizationCodeResourceDetails source) {
		super();
		
		//copy all other properties
		setUseCurrentUri(source.isUseCurrentUri());
		setUserAuthorizationUri(source.getUserAuthorizationUri());
		setPreEstablishedRedirectUri(source.getPreEstablishedRedirectUri());
		
		setId(source.getId());
		setClientId(source.getClientId());
		setAccessTokenUri(source.getAccessTokenUri());
		setScope(source.getScope());
		setClientSecret(source.getClientSecret());
		setClientAuthenticationScheme(source.getAuthenticationScheme());
		setAuthenticationScheme(source.getAuthenticationScheme());
		setTokenName(source.getTokenName());
		setGrantType(source.getGrantType());		
	}
	
	public AzureResourceDetails() {
		super();
	}
	
	public String getResponseType() {
		return responseType;
	}

	public void setResponseType(String value) {
		responseType = value;
	}
	
	
	public String getResponseMode() {
		return responseMode;
	}
	
	public void setResponseMode(String value) {
		responseMode = value;
	}	
	
	public String getResource() {
		return resource;
	}
	
	public void setResource(String value) {
		resource = value;
	}	
}
