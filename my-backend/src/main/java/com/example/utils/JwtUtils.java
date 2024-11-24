package com.example.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import jakarta.annotation.Resource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class JwtUtils {

    @Value("${spring.security.jwt.key}")
    String key;

    @Value("${spring.security.jwt.expire}")
    int expire;

    @Resource
    StringRedisTemplate template;

    //判断token是否有效,如果有效则加入黑名单
    public boolean invalidToken(String headerToken) {
        String token = this.convertToken(headerToken);
        if (token == null) {
            return false;
        }
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        try{
            DecodedJWT verify = jwtVerifier.verify(token);
            String id = verify.getId();
            return deleteToken(id, verify.getExpiresAt());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    //将token加入黑名单
    private boolean deleteToken(String uuid, Date time) {
        if (this.isInvalidToken(uuid)) {
            return false;
        }
        Date now = new Date();
        long expire = Math.max(time.getTime() - now.getTime(), 0);
        template.opsForValue().set(Const.JWT_BLACK_LIST + uuid, "", expire, TimeUnit.MICROSECONDS);
        return true;
    }

    //判断token是否在黑名单中
    private boolean isInvalidToken(String uuid) {
        return Boolean.TRUE.equals(template.hasKey(Const.JWT_BLACK_LIST + uuid));
    }

    public DecodedJWT resolveJwt(String headerToken) {
        // 将头部的 token 转换为实际的 JWT token
        String token = this.convertToken(headerToken);
        // 如果 token 为 null，返回 null
        if (token == null) {
            return null;
        }
        // 使用 HMAC256 算法和密钥创建算法实例
        Algorithm algorithm = Algorithm.HMAC256(key);
        // 创建 JWT 验证器
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        try {
            // 验证 token 并获取解码后的 JWT
            DecodedJWT verify = jwtVerifier.verify(token);
            // 如果 token 在黑名单中，返回 null
            if (this.isInvalidToken(verify.getId())) {
                return null;
            }
            // 获取 token 的过期时间
            Date expiresAt = verify.getExpiresAt();
            // 如果当前时间在过期时间之后，返回 null，否则返回解码后的 JWT
            return new Date().after(expiresAt) ? null : verify;
        } catch (JWTVerificationException e) {
            // 如果验证失败，返回 null
            return null;
        }
    }

    public String createJwt(UserDetails details, int id, String username) {
        // 使用 HMAC256 算法和密钥创建算法实例
        Algorithm algorithm = Algorithm.HMAC256(key);

        // 获取 JWT 的过期时间
        Date expireTime = this.expireTime();

        // 创建 JWT 并添加声明
        return JWT.create()
                .withJWTId(UUID.randomUUID().toString())
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

    public UserDetails toUser(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        return User
                .withUsername(claims.get("username").asString())
                .password("******")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }

    public int toId(DecodedJWT jwt) {
        Map<String, Claim> claims = jwt.getClaims();
        return claims.get("id").asInt();
    }

    private String convertToken(String headerToken) {
        if (headerToken == null || !headerToken.startsWith("Bearer ")) {
            return null;
        }
        return headerToken.substring(7);
    }
}
