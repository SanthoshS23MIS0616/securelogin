package com.intern.securelogin.controller;

import com.intern.securelogin.dto.LoginForm;
import com.intern.securelogin.dto.RegistrationForm;
import com.intern.securelogin.dto.TwoFactorForm;
import com.intern.securelogin.service.AccountService;
import com.intern.securelogin.service.AccountService.LoginResult;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class AuthController {

    private final AccountService accountService;

    public AuthController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/")
    public String home(Model model) {
        return isAuthenticated() ? "redirect:/dashboard" : login(model);
    }

    @GetMapping("/login")
    public String login(Model model) {
        if (isAuthenticated()) {
            return "redirect:/dashboard";
        }
        if (!model.containsAttribute("loginForm")) {
            model.addAttribute("loginForm", new LoginForm());
        }
        return "login";
    }

    @PostMapping("/login")
    public String login(
        @Valid @ModelAttribute("loginForm") LoginForm form,
        BindingResult bindingResult,
        HttpServletRequest request,
        RedirectAttributes redirectAttributes) {

        if (bindingResult.hasErrors()) {
            return "login";
        }

        LoginResult result = accountService.login(form, request);
        if (result.success()) {
            return "redirect:/dashboard";
        }
        if (result.requiresTwoFactor()) {
            redirectAttributes.addFlashAttribute("notice", result.message());
            return "redirect:/2fa";
        }

        bindingResult.reject("login.failed", result.message());
        return "login";
    }

    @GetMapping("/register")
    public String register(Model model) {
        if (isAuthenticated()) {
            return "redirect:/dashboard";
        }
        if (!model.containsAttribute("registrationForm")) {
            model.addAttribute("registrationForm", new RegistrationForm());
        }
        return "register";
    }

    @PostMapping("/register")
    public String register(
        @Valid @ModelAttribute("registrationForm") RegistrationForm form,
        BindingResult bindingResult,
        RedirectAttributes redirectAttributes) {

        if (!form.getPassword().equals(form.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch", "Password confirmation does not match.");
        }
        if (bindingResult.hasErrors()) {
            return "register";
        }

        try {
            accountService.register(form);
            redirectAttributes.addFlashAttribute("success", "Account created. You can sign in now.");
            return "redirect:/login";
        } catch (IllegalArgumentException ex) {
            bindingResult.reject("registration.failed", ex.getMessage());
            return "register";
        }
    }

    @GetMapping("/2fa")
    public String twoFactor(Model model) {
        if (isAuthenticated()) {
            return "redirect:/dashboard";
        }
        if (!model.containsAttribute("twoFactorForm")) {
            model.addAttribute("twoFactorForm", new TwoFactorForm());
        }
        return "two-factor";
    }

    @PostMapping("/2fa")
    public String verifyTwoFactor(
        @Valid @ModelAttribute("twoFactorForm") TwoFactorForm form,
        BindingResult bindingResult,
        HttpServletRequest request) {

        if (bindingResult.hasErrors()) {
            return "two-factor";
        }

        LoginResult result = accountService.verifyPendingTwoFactor(form.getCode(), request);
        if (result.success()) {
            return "redirect:/dashboard";
        }

        bindingResult.reject("twofactor.failed", result.message());
        return "two-factor";
    }

    private boolean isAuthenticated() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null
            && authentication.isAuthenticated()
            && !(authentication instanceof AnonymousAuthenticationToken);
    }
}
