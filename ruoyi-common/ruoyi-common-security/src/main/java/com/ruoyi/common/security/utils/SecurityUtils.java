package com.ruoyi.common.security.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.ruoyi.common.security.config.SecurityCofig;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import com.ruoyi.common.core.constant.CacheConstants;
import com.ruoyi.common.core.text.Convert;
import com.ruoyi.common.core.utils.ServletUtils;

import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

/**
 * 权限获取工具类
 *
 * @author ruoyi
 */
public class SecurityUtils {

  /**
   * jwtToken的算法
   */
  private static final Algorithm ALGORITHM = Algorithm.HMAC256("q1w2e3r4!@#$");


  /**
   * 获取用户
   */
  public static String getUsername() {
    return ServletUtils.getRequest().getHeader(CacheConstants.DETAILS_USERNAME);
  }

  /**
   * 获取用户ID
   */
  public static Long getUserId() {
    return Convert.toLong(ServletUtils.getRequest().getHeader(CacheConstants.DETAILS_USER_ID));
  }

  /**
   * 是否为管理员
   *
   * @param userId 用户ID
   * @return 结果
   */
  public static boolean isAdmin(Long userId) {
    return userId != null && 1L == userId;
  }

  /**
   * 生成BCryptPasswordEncoder密码
   *
   * @param password 密码
   * @return 加密字符串
   */
  public static String encryptPassword(String password) {
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    return passwordEncoder.encode(password);
  }

  /**
   * 判断密码是否相同
   *
   * @param rawPassword     真实密码
   * @param encodedPassword 加密后字符
   * @return 结果
   */
  public static boolean matchesPassword(String rawPassword, String encodedPassword) {
    BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    return passwordEncoder.matches(rawPassword, encodedPassword);
  }


  /**
   * 根据数据创建jwtToken
   *
   * @param map palyload的数据
   * @return token字符串
   */
  public static String getJwtToken(Map<String, Object> map) {

    //设置token过期时间
    Calendar instance = Calendar.getInstance();
    instance.add(Calendar.MINUTE, SecurityCofig.jwtTokenTimeout);

    //创建token
    String token = JWT.create().
            withClaim("info", map)//设置payload
            .withExpiresAt(instance.getTime())//设置过期时间
            .sign(ALGORITHM);
    return token;
  }


}
