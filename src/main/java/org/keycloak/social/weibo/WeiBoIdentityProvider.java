/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.weibo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.*;
import java.io.IOException;
import java.net.URI;
import java.util.UUID;

/**
 * OAuth2/authorize	请求用户授权Token
 *  OAuth2/access_token	获取授权过的Access Token
 *  OAuth2/get_token_info	授权信息查询接口
 *  OAuth2/revokeoauth2	授权回收接口
 *  授权交互流程：
 * //1 获取code
 *  https://api.weibo.com/oauth2/authorize?client_id=123050457758183&redirect_uri=REDIRECT_URL&response_type=code
 * //同意授权后会重定向你在微博配置的回调接口地址
 *  REDIRECT_URL&code=CODE&state=STATE(其中state是请求中所带，原样返回)
 *  代码中接收该回调对应方法：AbstractOAuth2IdentityProvider.Endpoint.authResponse
 * 2 获取token
 * https://api.weibo.com/oauth2/access_token?client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&grant_type=authorization_code&redirect_uri=YOUR_REGISTERED_REDIRECT_URI&code=CODE
 *3 获取用户信息
 * https://api.weibo.com/2/users/show.json?access_token=ACCESS_TOKEN
 * 
 * @author yong.jiang
 */
public class WeiBoIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
		implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {
//	//可变配置项
//	public static final String REDIRECT_URL = "http://127.0.0.1:8080/auth/realms/sinosun/broker/weibo/endpoint";
//	public static final String CLIENT_ID = "3612365606";
//	public static final String CLIENT_SECRET = "a1c12fc170d46865bf3f019e54c7599e";
//	//参数名
//	public static final String OAUTH2_PARAMETER_CLIENT_ID = "client_id";
//	public static final String OAUTH2_PARAMETER_CLIENT_SECRET = "client_secret";


//
//	public static final String WEIBO_AUTH_URL = "https://api.weibo.com/oauth2/authorize?" +
//			"client_id=" + CLIENT_ID +
//			"&redirect_uri=" + REDIRECT_URL +
//			"&response_type=code";
//	public static final String WEIBO_TOKEN_URL = "https://api.weibo.com/oauth2/access_token?" +
//			"client_id=" + CLIENT_ID +
//			"&client_secret=" + CLIENT_SECRET +
//			"&grant_type=authorization_code&redirect_uri=" + REDIRECT_URL +
//			"&code=AUTH_CODE";

	public static final String PROFILE_URL = "https://api.weibo.com/2/users/show.json?access_token=ACCESS_TOKEN&uid=UID";
	public static final String AUTH_URL = "https://api.weibo.com/oauth2/authorize";
	public static final String TOKEN_URL = "https://api.weibo.com/oauth2/access_token";
	/**
	 * all	请求下列所有scope权限
	 email	用户的联系邮箱，接口文档
	 direct_messages_write	私信发送接口，接口文档
	 direct_messages_read	私信读取接口，接口文档
	 invitation_write	邀请发送接口，接口文档
	 friendships_groups_read	好友分组读取接口组，接口文档
	 friendships_groups_write	好友分组写入接口组，接口文档
	 statuses_to_me_read	定向微博读取接口组，接口文档
	 follow_app_official_microblog
	 */
	public static final String DEFAULT_SCOPE = "statuses_to_me_read";



	public WeiBoIdentityProvider(KeycloakSession session, OAuth2IdentityProviderConfig config) {
		super(session, config);
		config.setAuthorizationUrl(AUTH_URL);
		config.setTokenUrl(TOKEN_URL);
	}

//	@Override
//	public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
//		return new Endpoint(callback, realm, event);
//	}

	@Override
	protected boolean supportsExternalExchange() {
		return true;
	}

	@Override
	protected BrokeredIdentityContext extractIdentityFromProfile(EventBuilder event, JsonNode profile) {
		String userId = getJsonProperty(profile, "id");
		logger.info("user id = "+userId);
		if (userId == null || userId.isEmpty()){
			throw new NullPointerException("user info is null " + profile.asText());
		}
		BrokeredIdentityContext user = new BrokeredIdentityContext(userId);
		
		user.setUsername(userId);
		user.setBrokerUserId(userId);
		user.setModelUsername(userId);
		user.setName(getJsonProperty(profile, "name"));
		user.setIdpConfig(getConfig());
		user.setIdp(this);
		AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
		return user;
	}

	@Override
	public BrokeredIdentityContext getFederatedIdentity(String response) {
		String accessToken = extractTokenFromResponse(response, getAccessTokenResponseParameter());
		if (accessToken == null) {
			throw new IdentityBrokerException("No access token available in OAuth server response: " + response);
		}
		BrokeredIdentityContext context = null;
		try {
			JsonNode profile = null;
			String uid = extractTokenFromResponse(response, "uid");
			String url = PROFILE_URL.replace("ACCESS_TOKEN", accessToken).replace("UID", uid);
			logger.info("---weibo get user info request = " + url);
			profile = SimpleHttp.doGet(url, session).asJson();
			logger.info("---weibo get userInfo = " + profile.toString());
			context = extractIdentityFromProfile(null, profile);
		} catch (IOException e) {
			logger.error(e);
		}
		context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
		return context;
	}
	
//	@Override
//	public Response performLogin(AuthenticationRequest request) {
//		try {
//			URI authorizationUrl = createAuthorizationUrl(request).build();
//			logger.info("---weibo auth request = " + authorizationUrl);
//			return Response.seeOther(authorizationUrl).build();
//		} catch (Exception e) {
//			throw new IdentityBrokerException("Could not create authentication request.", e);
//		}
//	}

	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}
	
//	@Override
//	protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
//		final UriBuilder uriBuilder;
//		uriBuilder = UriBuilder.fromUri(AUTH_URL);
//		uriBuilder.queryParam(OAUTH2_PARAMETER_SCOPE, getConfig().getDefaultScope())
//				.queryParam(OAUTH2_PARAMETER_STATE, request.getState().getEncoded())
//				.queryParam(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
//				.queryParam(OAUTH2_PARAMETER_REDIRECT_URI, REDIRECT_URL)
//				.queryParam(OAUTH2_PARAMETER_RESPONSE_TYPE, "code");
//
//		String loginHint = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);
//		if (getConfig().isLoginHint() && loginHint != null) {
//			uriBuilder.queryParam(OIDCLoginProtocol.LOGIN_HINT_PARAM, loginHint);
//		}
//
//		String prompt = getConfig().getPrompt();
//		if (prompt == null || prompt.isEmpty()) {
//			prompt = request.getAuthenticationSession().getClientNote(OAuth2Constants.PROMPT);
//		}
//		if (prompt != null) {
//			uriBuilder.queryParam(OAuth2Constants.PROMPT, prompt);
//		}
//
//		String nonce = request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.NONCE_PARAM);
//		if (nonce == null || nonce.isEmpty()) {
//			nonce = UUID.randomUUID().toString();
//			request.getAuthenticationSession().setClientNote(OIDCLoginProtocol.NONCE_PARAM, nonce);
//		}
//		uriBuilder.queryParam(OIDCLoginProtocol.NONCE_PARAM, nonce);
//
//		String acr = request.getAuthenticationSession().getClientNote(OAuth2Constants.ACR_VALUES);
//		if (acr != null) {
//			uriBuilder.queryParam(OAuth2Constants.ACR_VALUES, acr);
//		}
//		return uriBuilder;
//	}

//	protected class Endpoint {
//		protected AuthenticationCallback callback;
//		protected RealmModel realm;
//		protected EventBuilder event;
//
//		@Context
//		protected KeycloakSession session;
//
//		@Context
//		protected ClientConnection clientConnection;
//
//		@Context
//		protected HttpHeaders headers;
//
//		@Context
//		protected UriInfo uriInfo;
//
//		public Endpoint(AuthenticationCallback callback, RealmModel realm, EventBuilder event) {
//			this.callback = callback;
//			this.realm = realm;
//			this.event = event;
//		}
//
//		@GET
//		public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
//				@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
//				@QueryParam(OAuth2Constants.ERROR) String error) {
//			if (authorizationCode == null || "".equals(authorizationCode)){
//				return ErrorPage.error(session, null, Response.Status.UNAUTHORIZED,
//						Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
//			}
//			logger.info("---weibo authResponse OAUTH2_PARAMETER_CODE = " + authorizationCode);
//			if (error != null) {
//				if (error.equals(ACCESS_DENIED)) {
//					logger.error(ACCESS_DENIED + " for broker login " + getConfig().getProviderId());
//					return callback.cancelled(state);
//				} else {
//					logger.error(error + " for broker login " + getConfig().getProviderId());
//					return callback.error(state, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
//				}
//			}
//
//			try {
//				BrokeredIdentityContext federatedIdentity = null;
//				if (authorizationCode != null) {
//					String response = generateTokenRequest(authorizationCode).asString();
//					/**
//					 * response={"access_token":"2.00Je6shC5_HTwD3f3dcc2667rqrvHC","remind_in":"157679999",
//					 * "expires_in":157679999,"uid":"2480616413","isRealName":"true"}
//					 */
//					logger.info("---weibo get token response=" + response);
//					federatedIdentity = getFederatedIdentity(response);
//
//					if (getConfig().isStoreToken()) {
//						if (federatedIdentity.getToken() == null)
//							federatedIdentity.setToken(response);
//					}
//					federatedIdentity.setIdpConfig(getConfig());
//					federatedIdentity.setIdp(WeiBoIdentityProvider.this);
//					federatedIdentity.setCode(state);
//
//					return callback.authenticated(federatedIdentity);
//				}
//			} catch (WebApplicationException e) {
//				logger.error(" WebApplicationException " , e);
//				return e.getResponse();
//			} catch (Exception e) {
//				logger.error("Failed to make identity provider oauth callback ", e);
//			}
//			logger.info("some things wrong....");
//			event.event(EventType.LOGIN);
//			event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
//			return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY,
//					Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
//		}
//
//		public SimpleHttp generateTokenRequest(String authorizationCode) {
//
//			logger.info("---weibo get token request ...");
//			return SimpleHttp.doPost(TOKEN_URL, session)
//					.param(OAUTH2_PARAMETER_CLIENT_ID, getConfig().getClientId())
//					.param(OAUTH2_PARAMETER_CLIENT_SECRET, getConfig().getClientSecret())
//					.param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE)
//					.param(OAUTH2_PARAMETER_CODE, authorizationCode)
//					.param(OAUTH2_PARAMETER_REDIRECT_URI, uriInfo.getAbsolutePath().toString());
//		}
//
//	}
}
