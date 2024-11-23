package com.example.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.key}")
    String key;

    @Value("${spring.security.jwt.expire}")
    int expire;

    public String createJwt(UserDetails details, int id, String username) {
        // 使用 HMAC256 算法和密钥创建算法实例
        Algorithm algorithm = Algorithm.HMAC256(key);

        // 获取 JWT 的过期时间
        Date expireTime = this.expireTime();

        // 创建 JWT 并添加声明
        return JWT.create()
                .withClaim("id", id) // 添加用户 ID 声明
                .withClaim("username", username) // 添加用户名声明
                .withClaim("authorities", details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList()) // 添加用户权限声明
                .withExpiresAt(expireTime) // 设置过期时间
                .withIssuedAt(new Date()) // 设置签发时间
                .sign(algorithm); // 使用算法签名 JWT
    }

    public Date expireTime() {
        // 获取当前日期和时间
        Calendar calendar = Calendar.getInstance();
        // 添加过期时间（以小时为单位，expire * 24 小时）
        calendar.add(Calendar.HOUR, expire * 24);
        // 返回计算出的过期日期
        return calendar.getTime();
    }
}
