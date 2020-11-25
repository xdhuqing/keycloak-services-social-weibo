# keycloak-services-social-weibo
[服务介绍]
````
 keycloak Idp模式。使用第三方系统微博完成用户认证登录
````
### 微博登录接入
````
    1.将jar添加到keycloak服务器：
        $ cp targer/keycloak-services-social-weibo-*.jar _KEYCLOAK_HOME_/providers/
    2.将模板添加到keycloak服务器：
        $ cp templates/realm-identity-provider-weibo.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials
        $ cp templates/realm-identity-provider-weibo-ext.html _KEYCLOAK_HOME_/themes/base/admin/resources/partials  
    3.启动keycloak
````

 
