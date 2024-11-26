package com.example.entity.vo.request;

import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.hibernate.validator.constraints.Length;
import org.springframework.data.repository.cdi.Eager;

@Data
@AllArgsConstructor
public class EmailRestVO {

    @Email
    String email;
    @Length(min = 6, max = 6)
    String code;
    @Length(min = 5, max = 20)
    String password;
}
