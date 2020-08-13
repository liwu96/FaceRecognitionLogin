package com.sh.demo.common.config;

import com.sh.demo.common.shiro.ShiroRealm;
import com.sh.demo.common.shiro.ShiroSessionIdGenerator;
import com.sh.demo.common.shiro.ShiroSessionManager;
import com.sh.demo.common.util.SHA256Util;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * @Description Shiro配置类
 * @Author Sans
 * @CreateTime 2019/6/10 17:42
 */
@Configuration
public class ShiroConfig {

    @Autowired
    private RedisConfig redisConfig;

    //加密方式
    @Value("${richar.encryptionType}")
    private String encryptionType;

    //加密的散列次数
    @Value("${richar.hashNumbers}")
    private String hashNumbers;

    //默认登录页
    @Value("${shiro.login-url}")
    private String loginUrl;

    //权限拦击白名单
    @Value("${shiro.security-whitelist}")
    private List<String> whiteUrl;


    /**
     * 开启Shiro-aop注解支持
     * @Attention 使用代理方式所以需要开启代码支持
     * @CreateTime 2019/6/12 8:38
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * Shiro基础配置
     * @CreateTime 2019/6/12 8:42
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactory(SecurityManager securityManager){
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        // 注意过滤器配置顺序不能颠倒
        // 配置过滤:不会被拦截的链接
        //anon不需要授权的url
        //authc需要授权的的url
        for(String str:whiteUrl){
            filterChainDefinitionMap.put(str,"anon");
        }
//        filterChainDefinitionMap.put("/static/**", "anon");
//        filterChainDefinitionMap.put("/userLogin/**", "anon");
        filterChainDefinitionMap.put("/**", "authc");
        // 配置shiro默认登录界面地址，前后端分离中登录界面跳转应由前端路由控制，后台仅返回json数据
        shiroFilterFactoryBean.setLoginUrl(loginUrl);
        shiroFilterFactoryBean.setLoginUrl("/userLogin/unauth");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return shiroFilterFactoryBean;
    }

    /**
     * 安全管理器
     * @CreateTime 2019/6/12 10:34
     */
    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 自定义Ssession管理
        securityManager.setSessionManager(redisConfig.sessionManager());
        // 自定义Cache实现
        securityManager.setCacheManager(redisConfig.cacheManager());
        // 自定义Realm验证
        securityManager.setRealm(shiroRealm());
        return securityManager;
    }

    /**
     * 身份验证器

     * @CreateTime 2019/6/12 10:37
     */
    @Bean
    public ShiroRealm shiroRealm() {
        ShiroRealm shiroRealm = new ShiroRealm();
        shiroRealm.setCredentialsMatcher(hashedCredentialsMatcher());
        return shiroRealm;
    }

    /**
     * 凭证匹配器
     * 将密码校验交给Shiro的SimpleAuthenticationInfo进行处理,在这里做匹配配置
     * @CreateTime 2019/6/12 10:48
     */
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher shaCredentialsMatcher = new HashedCredentialsMatcher();
        // 散列算法:根据yml中配置
        shaCredentialsMatcher.setHashAlgorithmName(encryptionType);
        // 散列的次数，;
        shaCredentialsMatcher.setHashIterations(Integer.parseInt(hashNumbers));
        return shaCredentialsMatcher;
    }





}