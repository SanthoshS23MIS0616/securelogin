package com.intern.securelogin.service;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;

@Service
public class ClientInfoService {

    public String ipAddress(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        String rawIp = forwardedFor != null && !forwardedFor.isBlank()
            ? forwardedFor.split(",")[0].trim()
            : request.getRemoteAddr();
        return trim(rawIp, 64);
    }

    public String userAgent(HttpServletRequest request) {
        return trim(request.getHeader("User-Agent"), 240);
    }

    private String trim(String value, int maxLength) {
        if (value == null) {
            return "unknown";
        }
        String cleaned = value.replaceAll("[\\r\\n]", "").trim();
        return cleaned.length() <= maxLength ? cleaned : cleaned.substring(0, maxLength);
    }
}
