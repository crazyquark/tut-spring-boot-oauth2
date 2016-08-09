package com.example;

import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class AzureUserInfoTokenServices extends UserInfoTokenServices {

	public AzureUserInfoTokenServices(String userInfoEndpointUrl, String clientId) {
		super(userInfoEndpointUrl, clientId);
		
		this.setPrincipalExtractor(new AzurePrincipalExtractor());
	}
	
	@Override
	public OAuth2Authentication loadAuthentication(String accessToken)
			throws AuthenticationException, InvalidTokenException {
		OAuth2Authentication token = super.loadAuthentication(accessToken);
		
//		UsernamePasswordAuthenticationToken authToken =
//				(UsernamePasswordAuthenticationToken) token.getUserAuthentication();
//		
		
		return token;
	}
}
