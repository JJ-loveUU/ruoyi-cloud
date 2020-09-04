package com.ruoyi.common.security.service;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.servlet.http.HttpServletRequest;

import cn.hutool.core.convert.Convert;
import cn.hutool.core.lang.TypeReference;
import com.alibaba.fastjson.JSONObject;
import com.ruoyi.common.security.config.SecurityCofig;
import com.ruoyi.common.security.utils.SecurityUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.ruoyi.common.core.constant.CacheConstants;
import com.ruoyi.common.core.constant.Constants;
import com.ruoyi.common.core.utils.IdUtils;
import com.ruoyi.common.core.utils.ServletUtils;
import com.ruoyi.common.redis.service.RedisService;
import com.ruoyi.system.api.model.LoginUser;

/**
 * token验证处理
 *
 * @author ruoyi
 */
@Component
public class TokenService {
  @Autowired
  private RedisService redisService;

  private final static long EXPIRE_TIME = Constants.TOKEN_EXPIRE * 60;

  private final static String ACCESS_TOKEN = CacheConstants.LOGIN_TOKEN_KEY;

  protected static final long MILLIS_SECOND = 1000;

  /**
   * 创建令牌
   */
  public Map<String, Object> createToken(LoginUser loginUser) {
    // 生成token
    String token = IdUtils.fastUUID();
//    loginUser.setToken(token);

    Map<String, Object> loginUserMap = new HashMap<>();
    String
    loginUserMap.put("userid", loginUser.getSysUser().getUserId());
    loginUserMap.put("username", loginUser.getSysUser().getUserName());
    loginUserMap.put("loginTime", System.currentTimeMillis());
    loginUserMap.put("expireTime", loginUser.getLoginTime() + SecurityCofig.jwtTokenTimeout * 60 * MILLIS_SECOND);

    //生成map对象创建token
    String jwtToken = SecurityUtils.getJwtToken(loginUserMap);

    // 保存或更新用户token
    Map<String, Object> map = new HashMap<String, Object>();
    map.put("access_token", jwtToken);
    map.put("expires_in", EXPIRE_TIME);
    return map;
  }

  /**
   * 获取用户身份信息
   *
   * @return 用户信息
   */
  public LoginUser getLoginUser() {
    return getLoginUser(ServletUtils.getRequest());
  }

  /**
   * 获取用户身份信息
   *
   * @return 用户信息
   */
  public LoginUser getLoginUser(HttpServletRequest request) {
    // 获取请求携带的令牌
    String token = getToken(request);
    if (StringUtils.isNotEmpty(token)) {
      String userKey = getTokenKey(token);
      LoginUser user = redisService.getCacheObject(userKey);
      return user;
    }
    return null;
  }

  public void delLoginUser(String token) {
    if (StringUtils.isNotEmpty(token)) {
      String userKey = getTokenKey(token);
      redisService.deleteObject(userKey);
    }
  }

  /**
   * 刷新令牌有效期
   *
   * @param loginUser 登录信息
   */
  public Long refreshToken(LoginUser loginUser) {
    loginUser.setLoginTime(System.currentTimeMillis());
    loginUser.setExpireTime(loginUser.getLoginTime() + EXPIRE_TIME * MILLIS_SECOND);
    // 根据uuid将loginUser缓存
    String userKey = getTokenKey(loginUser.getToken());
    redisService.setCacheObject(userKey, loginUser, EXPIRE_TIME, TimeUnit.SECONDS);
    return EXPIRE_TIME;
  }

  private String getTokenKey(String token) {
    return ACCESS_TOKEN + token;
  }

  /**
   * 获取请求token
   */
  private String getToken(HttpServletRequest request) {
    String token = request.getHeader(CacheConstants.HEADER);
    if (StringUtils.isNotEmpty(token) && token.startsWith(CacheConstants.TOKEN_PREFIX)) {
      token = token.replace(CacheConstants.TOKEN_PREFIX, "");
    }
    return token;
  }

}