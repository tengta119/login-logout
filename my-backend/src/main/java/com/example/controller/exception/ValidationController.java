package com.example.controller.exception;

import com.example.entity.RestBean;
import lombok.extern.slf4j.Slf4j;
import net.sf.jsqlparser.util.validation.ValidationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ValidationController {

    @ExceptionHandler(ValidationException.class)
    public RestBean<Void> validateException(ValidationException e) {
        log.warn("ValidationException: {}", e.getMessage());
        return RestBean.failure(400,"参数校验失败");
    }
}






