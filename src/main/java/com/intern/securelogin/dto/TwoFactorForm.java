package com.intern.securelogin.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public class TwoFactorForm {

    @NotBlank(message = "Enter the 6-digit authenticator code.")
    @Pattern(regexp = "^\\d{6}$", message = "The code must be exactly 6 digits.")
    private String code;

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
