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
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;

import java.io.IOException;

/**
 *  授权交互流程：
 *  1 获取code
 *  https://api.weibo.com/oauth2/authorize?client_id=123050457758183&redirect_uri=REDIRECT_URL&response_type=code
 *  同意授权后会重定向你在微博配置的回调接口地址
 *  REDIRECT_URL&code=CODE&state=STATE(其中state是请求中所带，原样返回)
 *  代码中接收该回调对应方法：AbstractOAuth2IdentityProvider.Endpoint.authResponse
 *  2 获取token
 *  https://api.weibo.com/oauth2/access_token?client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&grant_type=authorization_code&redirect_uri=YOUR_REGISTERED_REDIRECT_URI&code=CODE
 *  3 获取用户信息
 *  https://api.weibo.com/2/users/show.json?access_token=ACCESS_TOKEN
 * 
 * @author qing.hu & kai.wang
 */
public class WeiBoIdentityProvider extends AbstractOAuth2IdentityProvider<OAuth2IdentityProviderConfig>
		implements SocialIdentityProvider<OAuth2IdentityProviderConfig> {

	/**
	 * 获取用户信息请求URL
	 */
	public static final String PROFILE_URL = "https://api.weibo.com/2/users/show.json?access_token=ACCESS_TOKEN&uid=UID";
	/**
	 * 授权请求URL
	 */
	public static final String AUTH_URL = "https://api.weibo.com/oauth2/authorize";
	/**
	 * 获取token请求URL
	 */
	public static final String TOKEN_URL = "https://api.weibo.com/oauth2/access_token";
	/**
	 all	请求下列所有scope权限
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

	@Override
	protected boolean supportsExternalExchange() {
		return true;
	}

	/**
	 * 提取微博用户信息，转换为keycloak用户实体
	 * @param event
	 * @param profile
	 * @return
	 */
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

	/**
	 * 获取微博用户信息
	 * @param response
	 * @return
	 */
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

	/**
	 * 获取默认授权范围
	 * @return
	 */
	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}
	
}
