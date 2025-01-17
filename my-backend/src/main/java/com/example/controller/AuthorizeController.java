package com.example.controller;

import com.example.entity.RestBean;
import com.example.entity.vo.request.ConfirmResetVO;
import com.example.entity.vo.request.EmailRegisterVO;
import com.example.entity.vo.request.EmailRestVO;
import com.example.service.AccountService;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.function.Supplier;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthorizeController {

    @Resource
    AccountService accountService;

    @GetMapping("/ask-code")
    public RestBean<Void> askVerifyCode(@RequestParam String email,
                                        @RequestParam @Pattern(regexp = "(register|reset)") String type,
                                        HttpServletRequest request) {
        return this.messageHandle(() -> accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr()));
    }

    @PostMapping("/register")
    public RestBean<Void> register(@RequestBody @Validated EmailRegisterVO emailRegisterVO) {
        return this.messageHandle(() -> accountService.registerEmailAccount(emailRegisterVO));
    }

    @PostMapping("/reset-confirm")
    public RestBean<Void> restConfirm(@RequestBody @Valid ConfirmResetVO vo) {
        return this.messageHandle(() -> accountService.restConfirm(vo));
    }

    @PostMapping("/reset-password")
    public RestBean<Void> restConfirm(@RequestBody @Valid EmailRestVO vo) {
        return this.messageHandle(() -> accountService.restEmailAccountPassword(vo));
    }

    private RestBean<Void> messageHandle(Supplier<String> action) {
        String message = action.get();
        return message == null ? RestBean.success() : RestBean.failure(400, message);
    }

}
