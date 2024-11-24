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



# Jwt请求头校验

用户每次向后端请求数据，会携带token，在SpringSecurity过滤链中进行校验

## SecurityConfiguration

```java
@Configuration
public class SecurityConfiguration {

    @Resource
    JwtUtils jwtUtils;

    @Resource
    JwtAuthorizeFilter jwtAuthorizeFilter;

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
                .exceptionHandling(conf -> conf
                        .authenticationEntryPoint(this::commence)
                        .accessDeniedHandler(this::handle)
                )
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(conf -> conf
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class)

                .build();
    }

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

    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

    }

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.unauthorized(exception.getMessage()).asJSONString());
    }

    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.forbidden(accessDeniedException.getMessage()).asJSONString());
    }

    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(RestBean.unauthorized(authException.getMessage()).asJSONString());
    }
}

```

添加过滤**addFilterBefore**

```java
addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class)
```

## JwtAuthorizeFilter

验证jwt

```java
@Component
public class JwtAuthorizeFilter extends OncePerRequestFilter { //过滤器

    @Resource
    JwtUtils jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        DecodedJWT jwt = jwtUtils.resolveJwt(authorization);
        if (jwt != null) {
            UserDetails user = jwtUtils.toUser(jwt);
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.setAttribute("id", jwtUtils.toId(jwt));
        }
        filterChain.doFilter(request, response);
    }
}
```





# Jwt退出登录 

[redis基本部署](https://blog.csdn.net/sss1513/article/details/144004502)

使用redis实现黑名单功能，用户在退出登录时会将token的uuid存放在redis数据库上，用户在每次请求数据时，后端会校验**token是否合法**，然后校验**是否在黑名单中**，如果这两项其中有一个不符合要求则拒绝请求

```java
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
```

