package com.intern.securelogin.controller;

import com.intern.securelogin.dto.PasswordChangeForm;
import com.intern.securelogin.entity.AppUser;
import com.intern.securelogin.repository.UserRepository;
import com.intern.securelogin.service.AccountService;
import com.intern.securelogin.service.TotpService;
import jakarta.servlet.http.HttpSession;
import jakarta.validation.Valid;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class SecuritySettingsController {

    private final UserRepository userRepository;
    private final AccountService accountService;
    private final TotpService totpService;

    public SecuritySettingsController(UserRepository userRepository, AccountService accountService, TotpService totpService) {
        this.userRepository = userRepository;
        this.accountService = accountService;
        this.totpService = totpService;
    }

    @GetMapping("/security")
    public String security(@AuthenticationPrincipal UserDetails principal, HttpSession session, Model model) {
        populateSecurityModel(principal, session, model);
        return "security";
    }

    @PostMapping("/security/password")
    public String changePassword(
        @AuthenticationPrincipal UserDetails principal,
        HttpSession session,
        @Valid @ModelAttribute("passwordChangeForm") PasswordChangeForm form,
        BindingResult bindingResult,
        Model model,
        RedirectAttributes redirectAttributes) {

        if (!form.getNewPassword().equals(form.getConfirmPassword())) {
            bindingResult.rejectValue("confirmPassword", "password.mismatch", "New password confirmation does not match.");
        }
        if (bindingResult.hasErrors()) {
            populateSecurityModel(principal, session, model);
            return "security";
        }

        try {
            accountService.changePassword(currentUser(principal), form);
            redirectAttributes.addFlashAttribute("success", "Password updated securely.");
            return "redirect:/security";
        } catch (IllegalArgumentException ex) {
            bindingResult.reject("password.failed", ex.getMessage());
            populateSecurityModel(principal, session, model);
            return "security";
        }
    }

    @PostMapping("/security/2fa/start")
    public String startTwoFactor(
        @AuthenticationPrincipal UserDetails principal,
        HttpSession session,
        RedirectAttributes redirectAttributes) {

        AppUser user = currentUser(principal);
        if (user.isTwoFactorEnabled()) {
            redirectAttributes.addFlashAttribute("notice", "Two-factor authentication is already active.");
            return "redirect:/security";
        }

        session.setAttribute(AccountService.TWO_FACTOR_SETUP_SECRET, totpService.generateSecret());
        redirectAttributes.addFlashAttribute("notice", "Add the setup key to your authenticator app, then verify the code.");
        return "redirect:/security";
    }

    @PostMapping("/security/2fa/enable")
    public String enableTwoFactor(
        @AuthenticationPrincipal UserDetails principal,
        HttpSession session,
        @RequestParam("code") String code,
        RedirectAttributes redirectAttributes) {

        String secret = (String) session.getAttribute(AccountService.TWO_FACTOR_SETUP_SECRET);
        try {
            accountService.enableTwoFactor(currentUser(principal), secret, code);
            session.removeAttribute(AccountService.TWO_FACTOR_SETUP_SECRET);
            redirectAttributes.addFlashAttribute("success", "Two-factor authentication is now protecting your account.");
        } catch (IllegalArgumentException ex) {
            redirectAttributes.addFlashAttribute("securityError", ex.getMessage());
        }
        return "redirect:/security";
    }

    @PostMapping("/security/2fa/disable")
    public String disableTwoFactor(
        @AuthenticationPrincipal UserDetails principal,
        @RequestParam("currentPassword") String currentPassword,
        @RequestParam("code") String code,
        RedirectAttributes redirectAttributes) {

        try {
            accountService.disableTwoFactor(currentUser(principal), currentPassword, code);
            redirectAttributes.addFlashAttribute("success", "Two-factor authentication has been disabled.");
        } catch (IllegalArgumentException ex) {
            redirectAttributes.addFlashAttribute("securityError", ex.getMessage());
        }
        return "redirect:/security";
    }

    private void populateSecurityModel(UserDetails principal, HttpSession session, Model model) {
        AppUser user = currentUser(principal);
        Object setupSecret = session.getAttribute(AccountService.TWO_FACTOR_SETUP_SECRET);
        model.addAttribute("user", user);
        if (!model.containsAttribute("passwordChangeForm")) {
            model.addAttribute("passwordChangeForm", new PasswordChangeForm());
        }
        if (setupSecret instanceof String secret) {
            model.addAttribute("setupSecret", secret);
            model.addAttribute("otpAuthUri", totpService.buildOtpAuthUri(user.getEmail(), secret));
        }
    }

    private AppUser currentUser(UserDetails principal) {
        return userRepository.findByEmail(principal.getUsername())
            .orElseThrow(() -> new IllegalStateException("Signed-in account was not found"));
    }
}
