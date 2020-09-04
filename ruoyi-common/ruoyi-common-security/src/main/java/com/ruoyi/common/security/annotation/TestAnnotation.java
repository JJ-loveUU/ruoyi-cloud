package com.ruoyi.common.security.annotation;

import org.springframework.cloud.openfeign.EnableFeignClients;

import java.lang.annotation.*;

/**
 * @Author yh
 * @Date 2020/9/3 10:11
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@EnableRyFeignClients
public @interface TestAnnotation {

  String[] basePackages() default { "com.ruoyi" };
}
