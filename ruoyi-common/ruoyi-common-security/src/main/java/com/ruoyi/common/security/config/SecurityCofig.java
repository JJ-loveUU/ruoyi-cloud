package com.ruoyi.common.security.config;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.stereotype.Component;

/**
 * @Author yh
 * @Date 2020/9/4 16:56
 */
@Component
@RefreshScope
public class SecurityCofig {

  /**
   * jwt token过期时间,分钟
   */
  @Value("${jwtTokenTimeout}")
  public static Integer jwtTokenTimeout = 30;

}
