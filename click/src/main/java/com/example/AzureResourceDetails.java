package com.example;

import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
/**
 * Configuration settings for the Azure OpenId authentication
 * 
 * For full list of Azure call parameters, see 
 * https://azure.microsoft.com/en-us/documentation/articles/active-directory-protocols-openid-connect-code/
 * @author Alex Baloc
 *
 */
public class AzureResourceDetails extends AuthorizationCodeResourceDetails {
  private String responseType = "code id_token";
  private String responseMode = "form_post";
  private String resource;
  private String prompt;
  
  private String logoutUri;
  private String logoutRedirectUri;
  
  //TOOD: this should probably be extracted from somewhere else, as it's more of a state than configuration field
  private String loginHint;

  public AzureResourceDetails(AuthorizationCodeResourceDetails source) {
    super();

    // copy all other properties
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
  
  /**
   * What kind of token to request from Azure. 
   * Default: code + token_id
   */
  public String getResponseType() {
    return responseType;
  }

  /**
   * What kind of token to request from Azure. 
   * Default: code + token_id
   */  
  public void setResponseType(String value) {
    responseType = value;
  }

  /**
   * How Azure will call back the application. 
   * Supported modes:form_post (default) or fragment
   */
  public String getResponseMode() {
    return responseMode;
  }

  /**
   * How Azure will call back the application. 
   * Supported modes:form_post (defautl) or fragment
   */  
  public void setResponseMode(String value) {
    responseMode = value;
  }

  public String getResource() {
    return resource;
  }

  public void setResource(String value) {
    resource = value;
  }
  
  /**
   * Type of user interaction required for the login.
   * Supported modes: null (default), login (disable SSO), none or consent
   */
  public String getPrompt() {
    return prompt;
  }
  
  /**
   * Type of user interaction required for the login.
   * Supported modes: null (default), login (disable SSO), none or consent
   */  
  public void setPrompt(String value) {
    prompt = value;
  }
  
  /**
   * Pre-filled username to log on with
   */  
  public String getLoginHint() {
    return loginHint;
  }
  
  /**
   * Pre-filled username to log on with
   */
  public void setLoginHint(String value) {
    loginHint = value;
  }

  /**
   * URI to call when closing the azure session
   */  
  public String getLogoutUri() {
    return logoutUri;
  }
  
  /**
   * URI to call when closing the azure session
   */    
  public void setLogoutUri(String value) {
    logoutUri = value;
  }
  
  /**
   * URI to redirect the client to after an Azure logout
   */    
  public String getLogoutRedirectUri() {
    return logoutRedirectUri;
  }

  /**
   * URI to redirect the client to after an Azure logout
   */      
  public void setLogoutRedirectUri(String value) {
    logoutRedirectUri = value;
  }
}
