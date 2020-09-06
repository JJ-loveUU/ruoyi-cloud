package com.ruoyi.auth;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.cloud.client.SpringCloudApplication;
import com.ruoyi.common.security.annotation.EnableRyFeignClients;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * 认证授权中心
 *
 * @author ruoyi
 */
@EnableRyFeignClients
@SpringCloudApplication
@ComponentScan("com.ruoyi")
public class RuoYiAuthApplication {


  public static void main(String[] args) {

    SpringApplication.run(RuoYiAuthApplication.class, args);
    System.out.println("(♥◠‿◠)ﾉﾞ  认证授权中心启动成功   ლ(´ڡ`ლ)ﾞ  \n" +
            " .-------.       ____     __        \n" +
            " |  _ _   \\      \\   \\   /  /    \n" +
            " | ( ' )  |       \\  _. /  '       \n" +
            " |(_ o _) /        _( )_ .'         \n" +
            " | (_,_).' __  ___(_ o _)'          \n" +
            " |  |\\ \\  |  ||   |(_,_)'         \n" +
            " |  | \\ `'   /|   `-'  /           \n" +
            " |  |  \\    /  \\      /           \n" +
            " ''-'   `'-'    `-..-'              ");
  }
}
