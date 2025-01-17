package com.example.entity.vo.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.hibernate.validator.constraints.Length;

@Data
public class EmailRegisterVO {

    @Length(min = 4)
    @Email
    String email;
    @Length(max = 6, min = 6)
    String code;
    @Pattern(regexp = "[a-zA-Z0-9\\u4e00-\\u9fa5]+$")
            @Length(max = 10, min = 1)
    String username;
    @Length(max = 20, min = 6)
    String password;
}
