package com.intern.securelogin.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class TotpServiceTests {

    @Test
    void generatedCurrentCodeIsAccepted() {
        TotpService totpService = new TotpService();
        String secret = totpService.generateSecret();
        long currentStep = System.currentTimeMillis() / 1000L / 30L;
        String code = totpService.generateCode(secret, currentStep);

        assertThat(totpService.isValidCode(secret, code)).isTrue();
    }

    @Test
    void malformedCodeIsRejected() {
        TotpService totpService = new TotpService();

        assertThat(totpService.isValidCode(totpService.generateSecret(), "12A456")).isFalse();
    }
}
