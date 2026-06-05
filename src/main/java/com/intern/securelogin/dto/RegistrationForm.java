package com.intern.securelogin.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class RegistrationForm {

    @NotBlank(message = "Full name is required.")
    @Size(min = 2, max = 80, message = "Use 2 to 80 characters.")
    @Pattern(regexp = "^[A-Za-z][A-Za-z .'-]{1,79}$", message = "Use letters, spaces, apostrophes, dots, or hyphens.")
    private String fullName;

    @NotBlank(message = "Email is required.")
    @Email(message = "Enter a valid email address.")
    @Size(max = 120, message = "Email is too long.")
    private String email;

    @NotBlank(message = "Password is required.")
    @Size(min = 12, max = 128, message = "Use 12 to 128 characters.")
    @Pattern(
        regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[^A-Za-z0-9]).+$",
        message = "Use uppercase, lowercase, number, and symbol characters.")
    private String password;

    @NotBlank(message = "Confirm your password.")
    private String confirmPassword;

    @AssertTrue(message = "Accept the security promise to continue.")
    private boolean securityPromise;

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public boolean isSecurityPromise() {
        return securityPromise;
    }

    public void setSecurityPromise(boolean securityPromise) {
        this.securityPromise = securityPromise;
    }
}
