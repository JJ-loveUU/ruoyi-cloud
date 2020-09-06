package com.ruoyi.gateway.filter;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.exceptions.AlgorithmMismatchException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.ruoyi.common.core.constant.Constants;
import com.ruoyi.common.core.utils.ServletUtils;
import com.ruoyi.common.security.utils.SecurityUtils;
import com.sun.org.apache.xml.internal.security.signature.InvalidSignatureValueException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.ruoyi.common.core.constant.CacheConstants;
import com.ruoyi.common.core.domain.R;
import com.ruoyi.common.core.utils.StringUtils;
import reactor.core.publisher.Mono;

/**
 * 网关鉴权
 *
 * @author ruoyi
 */
@Component
public class AuthFilter implements GlobalFilter, Ordered {
  private static final Logger log = LoggerFactory.getLogger(AuthFilter.class);

  // 排除过滤的 uri 地址，swagger排除自行添加
  private static final String[] whiteList = {"/auth/login" , "/code/v2/api-docs" , "/schedule/v2/api-docs" ,
          "/system/v2/api-docs" , "/csrf"};

  @Resource(name = "stringRedisTemplate")
  private ValueOperations<String, String> sops;

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {


    String url = exchange.getRequest().getURI().getPath();
    // 跳过不需要验证的路径
    if (Arrays.asList(whiteList).contains(url)) {
      return chain.filter(exchange);
    }
//        String token = getToken(exchange.getRequest());

    List<String> authorization = exchange.getRequest().getHeaders().get("authorization");
    String token = "";
    if (StringUtils.isNotEmpty(authorization)) {
      token = authorization.get(0);
    }

    if (StringUtils.isBlank(token)) {
      return setUnauthorizedResponse(exchange, "令牌不能为空");
    }


    //验证token
    DecodedJWT decodedJWT = null;
    try {
      decodedJWT = SecurityUtils.verify(token);
    } catch (SignatureVerificationException e) {
      return setUnauthorizedResponse(exchange, "无效签名");
    } catch (TokenExpiredException e) {
      return setUnauthorizedResponse(exchange, "token过期");

    } catch (AlgorithmMismatchException e) {
      return setUnauthorizedResponse(exchange, "token算法不一致");

    } catch (Exception e) {
      return setUnauthorizedResponse(exchange, "token无效");
    }
    //获取token中的用户信息
    Map<String, Object> loginUser = decodedJWT.getClaim("info").asMap();

    if (StringUtils.isNull(loginUser)) {
      return setUnauthorizedResponse(exchange, "loginUser数据不存在");
    }

    String userid = String.valueOf(loginUser.get("userid"));
    String username = (String) loginUser.get("username");
    if (StringUtils.isBlank(userid) || StringUtils.isBlank(username)) {
      return setUnauthorizedResponse(exchange, "令牌验证失败");
    }
    // 设置用户信息到请求
    ServerHttpRequest mutableReq = exchange.getRequest().mutate().header(CacheConstants.DETAILS_USER_ID, userid)
            .header(CacheConstants.DETAILS_USERNAME, username).build();
    ServerWebExchange mutableExchange = exchange.mutate().request(mutableReq).build();

    return chain.filter(mutableExchange);
  }

  private Mono<Void> setUnauthorizedResponse(ServerWebExchange exchange, String msg) {
    ServerHttpResponse response = exchange.getResponse();
    response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
    response.setStatusCode(HttpStatus.OK);

    log.error("[鉴权异常处理]请求路径:{}" , exchange.getRequest().getPath());

    return response.writeWith(Mono.fromSupplier(() -> {
      DataBufferFactory bufferFactory = response.bufferFactory();
      return bufferFactory.wrap(JSON.toJSONBytes(R.fail(com.ruoyi.common.core.constant.HttpStatus.UNAUTHORIZED, msg)));
    }));
  }

  /**
   * 获取请求token
   */
  private String getToken(ServerHttpRequest request) {
    String token = request.getHeaders().getFirst(CacheConstants.HEADER);
    if (StringUtils.isNotEmpty(token) && token.startsWith(CacheConstants.TOKEN_PREFIX)) {
      token = token.replace(CacheConstants.TOKEN_PREFIX, "");
    }
    return token;
  }

  @Override
  public int getOrder() {
    return -200;
  }
}