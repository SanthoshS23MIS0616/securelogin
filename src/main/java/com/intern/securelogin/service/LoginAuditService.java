package com.intern.securelogin.service;

import com.intern.securelogin.entity.AppUser;
import com.intern.securelogin.entity.LoginEvent;
import com.intern.securelogin.repository.LoginEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public class LoginAuditService {

    private final LoginEventRepository loginEventRepository;
    private final ClientInfoService clientInfoService;

    public LoginAuditService(LoginEventRepository loginEventRepository, ClientInfoService clientInfoService) {
        this.loginEventRepository = loginEventRepository;
        this.clientInfoService = clientInfoService;
    }

    public void record(AppUser user, String email, boolean success, String reason, HttpServletRequest request) {
        loginEventRepository.save(new LoginEvent(
            user == null ? null : user.getId(),
            email == null || email.isBlank() ? "unknown" : email.toLowerCase(),
            success,
            reason,
            clientInfoService.ipAddress(request),
            clientInfoService.userAgent(request)));
    }
}
