package com.example.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.entity.dto.Account;
import com.example.entity.vo.request.EmailRegisterVO;
import com.example.mapper.AccountMapper;
import com.example.service.AccountService;
import com.example.utils.Const;
import com.example.utils.FlowUtils;
import jakarta.annotation.Resource;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {

    @Resource
    AmqpTemplate amqpTemplate;
    @Resource
    StringRedisTemplate stringRedisTemplate;
    @Resource
    FlowUtils flowUtils;

    @Resource
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = this.findAccountByNameOrEmail(username);
        if (account == null) {
            throw new UsernameNotFoundException("用户名或密码错误");
        }
        return User
                .withUsername(username)
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }


    @Override
    public Account findAccountByNameOrEmail(String text) {
        return this.query()
                .eq("username", text)
                .or()
                .eq("email", text)
                .one();
    }

    @Override
    public String registerEmailVerifyCode(String type, String email, String ip) {
        synchronized (ip.intern()) {
            if (!this.verifyLimit(ip)) {
                return "请求过于频繁";
            }
            Random random = new Random();
            int code = random.nextInt(899999) + 100000;
            Map<String, Object> data = Map.of("type", type, "email", email, "code", code);
            amqpTemplate.convertAndSend("mail", data);
            stringRedisTemplate.opsForValue()
                    .set(Const.VERIFY_EMAIL_DATA + email, String.valueOf(code), 3, TimeUnit.MINUTES);
            return null;
        }
    }

    @Override
    public String registerEmailAccount(EmailRegisterVO emailRegisterVO) {
        String email = emailRegisterVO.getEmail();
        String code = stringRedisTemplate.opsForValue().get(Const.VERIFY_EMAIL_DATA + email);
        if (code == null || !code.equals(emailRegisterVO.getCode())) {
            return "验证码错误";
        }
        if (this.existsAccountByEmail(email)) {
            return "邮箱已被注册";
        }
        if (this.existsAccountByUsername(emailRegisterVO.getUsername())) {
            return "用户名已被注册";
        }
        Account account = new Account(null, emailRegisterVO.getUsername(), passwordEncoder.encode(emailRegisterVO.getPassword()), email, "user", new Date());
        if (this.save(account)) {
            stringRedisTemplate.delete(Const.VERIFY_EMAIL_DATA + email);
            return null;
        } else {
            return "内部错误，请稍后再试";
        }
    }

    private boolean existsAccountByEmail(String email) {
        return this.baseMapper.exists(Wrappers.<Account>query().eq("email", email));
    }

    private boolean existsAccountByUsername(String username) {
        return this.baseMapper.exists(Wrappers.<Account>query().eq("username", username));
    }

    private boolean verifyLimit(String ip) {
        String key = Const.VERIFY_EMAIL_LIMIT + ip;
        return flowUtils.limitOnceCheck(key,60);
    }
}
