package com.intern.securelogin.controller;

import com.intern.securelogin.entity.AppUser;
import com.intern.securelogin.repository.LoginEventRepository;
import com.intern.securelogin.repository.UserRepository;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class DashboardController {

    private final UserRepository userRepository;
    private final LoginEventRepository loginEventRepository;

    public DashboardController(UserRepository userRepository, LoginEventRepository loginEventRepository) {
        this.userRepository = userRepository;
        this.loginEventRepository = loginEventRepository;
    }

    @GetMapping("/dashboard")
    public String dashboard(@AuthenticationPrincipal UserDetails principal, Model model) {
        AppUser user = currentUser(principal);
        int securityScore = securityScore(user);
        model.addAttribute("user", user);
        model.addAttribute("events", loginEventRepository.findTop10ByUserIdOrderByCreatedAtDesc(user.getId()));
        model.addAttribute("securityScore", securityScore);
        model.addAttribute("securityLevel", securityLevel(securityScore));
        model.addAttribute("ringOffset", 314 - (314 * securityScore / 100));
        return "dashboard";
    }

    private AppUser currentUser(UserDetails principal) {
        return userRepository.findByEmail(principal.getUsername())
            .orElseThrow(() -> new IllegalStateException("Signed-in account was not found"));
    }

    private int securityScore(AppUser user) {
        int score = 50;
        if (user.isTwoFactorEnabled()) {
            score += 25;
        }
        if (user.getFailedAttempts() == 0 && !user.isLocked()) {
            score += 15;
        }
        if (user.getLastLoginAt() != null) {
            score += 10;
        }
        return Math.min(score, 100);
    }

    private String securityLevel(int score) {
        if (score >= 90) {
            return "Fortified";
        }
        if (score >= 75) {
            return "Strong";
        }
        if (score >= 60) {
            return "Improving";
        }
        return "Needs attention";
    }
}
