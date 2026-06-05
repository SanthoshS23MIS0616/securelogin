package com.intern.securelogin.service;

import com.intern.securelogin.dto.LoginForm;
import com.intern.securelogin.dto.PasswordChangeForm;
import com.intern.securelogin.dto.RegistrationForm;
import com.intern.securelogin.entity.AppUser;
import com.intern.securelogin.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Duration;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@Service
public class AccountService {

    public static final String PENDING_2FA_USER_ID = "PENDING_2FA_USER_ID";
    public static final String TWO_FACTOR_SETUP_SECRET = "TWO_FACTOR_SETUP_SECRET";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginAuditService loginAuditService;
    private final TotpService totpService;
    private final int maxFailedAttempts;
    private final Duration lockDuration;

    public AccountService(
        UserRepository userRepository,
        PasswordEncoder passwordEncoder,
        LoginAuditService loginAuditService,
        TotpService totpService,
        @Value("${app.security.max-failed-attempts:5}") int maxFailedAttempts,
        @Value("${app.security.lock-minutes:10}") long lockMinutes) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginAuditService = loginAuditService;
        this.totpService = totpService;
        this.maxFailedAttempts = maxFailedAttempts;
        this.lockDuration = Duration.ofMinutes(lockMinutes);
    }

    @Transactional
    public void register(RegistrationForm form) {
        String email = normalizeEmail(form.getEmail());
        if (!form.getPassword().equals(form.getConfirmPassword())) {
            throw new IllegalArgumentException("Password confirmation does not match.");
        }
        if (userRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("An account already exists for this email.");
        }

        String cleanName = form.getFullName().trim().replaceAll("\\s+", " ");
        userRepository.save(new AppUser(cleanName, email, passwordEncoder.encode(form.getPassword())));
    }

    @Transactional
    public LoginResult login(LoginForm form, HttpServletRequest request) {
        String email = normalizeEmail(form.getEmail());
        AppUser user = userRepository.findByEmail(email).orElse(null);

        if (user == null) {
            loginAuditService.record(null, email, false, "Unknown account", request);
            return LoginResult.failure("Invalid email or password.");
        }

        if (user.isLocked()) {
            loginAuditService.record(user, email, false, "Account locked", request);
            return LoginResult.failure("Account is temporarily locked. Try again later.");
        }

        if (!passwordEncoder.matches(form.getPassword(), user.getPasswordHash())) {
            registerFailedAttempt(user, request, "Invalid password");
            return LoginResult.failure("Invalid email or password.");
        }

        if (user.isTwoFactorEnabled()) {
            request.getSession(true).setAttribute(PENDING_2FA_USER_ID, user.getId());
            loginAuditService.record(user, email, false, "Password accepted; 2FA required", request);
            return LoginResult.twoFactorRequired();
        }

        completeLogin(user, request);
        return LoginResult.loggedIn();
    }

    @Transactional
    public LoginResult verifyPendingTwoFactor(String code, HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute(PENDING_2FA_USER_ID) == null) {
            return LoginResult.failure("Your 2FA session expired. Please log in again.");
        }

        Long userId = (Long) session.getAttribute(PENDING_2FA_USER_ID);
        AppUser user = userRepository.findById(userId)
            .orElseThrow(() -> new IllegalStateException("Pending account was not found"));

        if (user.isLocked()) {
            loginAuditService.record(user, user.getEmail(), false, "Account locked during 2FA", request);
            return LoginResult.failure("Account is temporarily locked. Try again later.");
        }

        if (!totpService.isValidCode(user.getTwoFactorSecret(), code)) {
            registerFailedAttempt(user, request, "Invalid 2FA code");
            return LoginResult.failure("Authenticator code is incorrect.");
        }

        completeLogin(user, request);
        return LoginResult.loggedIn();
    }

    @Transactional
    public void changePassword(AppUser user, PasswordChangeForm form) {
        if (!passwordEncoder.matches(form.getCurrentPassword(), user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect.");
        }
        if (!form.getNewPassword().equals(form.getConfirmPassword())) {
            throw new IllegalArgumentException("New password confirmation does not match.");
        }
        user.setPasswordHash(passwordEncoder.encode(form.getNewPassword()));
        userRepository.save(user);
    }

    @Transactional
    public void enableTwoFactor(AppUser user, String secret, String code) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("Start 2FA setup first.");
        }
        if (!totpService.isValidCode(secret, code)) {
            throw new IllegalArgumentException("Authenticator code is incorrect.");
        }
        user.setTwoFactorSecret(secret);
        user.setTwoFactorEnabled(true);
        userRepository.save(user);
    }

    @Transactional
    public void disableTwoFactor(AppUser user, String currentPassword, String code) {
        if (!passwordEncoder.matches(currentPassword, user.getPasswordHash())) {
            throw new IllegalArgumentException("Current password is incorrect.");
        }
        if (user.isTwoFactorEnabled() && !totpService.isValidCode(user.getTwoFactorSecret(), code)) {
            throw new IllegalArgumentException("Authenticator code is incorrect.");
        }
        user.setTwoFactorEnabled(false);
        user.setTwoFactorSecret(null);
        userRepository.save(user);
    }

    public String normalizeEmail(String email) {
        return email == null ? "" : email.trim().toLowerCase();
    }

    private void registerFailedAttempt(AppUser user, HttpServletRequest request, String reason) {
        user.setFailedAttempts(user.getFailedAttempts() + 1);
        if (user.getFailedAttempts() >= maxFailedAttempts) {
            user.setLockedUntil(Instant.now().plus(lockDuration));
        }
        userRepository.save(user);
        loginAuditService.record(user, user.getEmail(), false, reason, request);
    }

    private void completeLogin(AppUser user, HttpServletRequest request) {
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);
        loginAuditService.record(user, user.getEmail(), true, "Login successful", request);
        authenticateSession(user, request);
    }

    private void authenticateSession(AppUser appUser, HttpServletRequest request) {
        UserDetails principal = User.withUsername(appUser.getEmail())
            .password(appUser.getPasswordHash())
            .authorities("ROLE_USER")
            .build();
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
            principal,
            null,
            principal.getAuthorities());
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        HttpSession session = request.getSession(true);
        request.changeSessionId();
        session = request.getSession(false);
        session.removeAttribute(PENDING_2FA_USER_ID);
        session.removeAttribute(TWO_FACTOR_SETUP_SECRET);
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, context);
    }

    public record LoginResult(boolean success, boolean requiresTwoFactor, String message) {

        static LoginResult loggedIn() {
            return new LoginResult(true, false, "Welcome back.");
        }

        static LoginResult twoFactorRequired() {
            return new LoginResult(false, true, "Enter your authenticator code.");
        }

        static LoginResult failure(String message) {
            return new LoginResult(false, false, message);
        }
    }
}
