# 配置SpringSecurity基本内容

## SecurityConfiguration

```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/api/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login")
                        .successHandler(this::onAuthenticationSuccess)
                        .failureHandler(this::onAuthenticationFailure)
                )
                .logout(conf -> conf
                        .logoutUrl("/api/auth/logout")
                        .logoutSuccessHandler(this::onLogoutSuccess)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .build();
    }

    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.success().asJSONString());
    }

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.failure(401,exception.getMessage()).asJSONString());
    }

    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

    }
}
```



## RestBean

```java
public record RestBean<T>(int code, T data, String message) {

    public static <T> RestBean<T> success(T data) {
        return new RestBean<>(200, data, "请求成功");
    }

    public static <T> RestBean<T> success() {
        return success(null);
    }

    public static <T> RestBean<T> failure(int code, String message) {
        return new RestBean<>(code, null, message);
    }

    public String asJSONString() {
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
```



# Jwt令牌颁发

## JwtUtils

```java
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
```

## entity

### dto

数据库层面用dto

### vo

跟前端交互用vo

提交给前端

```java
@Data
public class AuthorizeVO {
    String username;
    String role;
    String token;
    Date expireTime;
}
```



## SecurityConfiguration

```java
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        User principal = (User) authentication.getPrincipal();
        String token = jwtUtils.createJwt(principal, 1, "小明");

        AuthorizeVO authorizeVO = new AuthorizeVO();
        authorizeVO.setToken(token);
        authorizeVO.setRole("");
        authorizeVO.setExpireTime(jwtUtils.expireTime());
        authorizeVO.setUsername("小明");

        response.getWriter().write(RestBean.success(authorizeVO).asJSONString());
    }
```

