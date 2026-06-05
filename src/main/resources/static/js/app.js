document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".reveal-password").forEach((button) => {
        button.addEventListener("click", () => {
            const input = button.parentElement.querySelector("input");
            const hidden = input.type === "password";
            input.type = hidden ? "text" : "password";
            button.textContent = hidden ? "Hide" : "View";
            button.setAttribute("aria-label", hidden ? "Hide password" : "Show password");
        });
    });

    document.querySelectorAll(".strength-input").forEach((input) => {
        const wrapper = input.closest("label");
        const track = wrapper ? wrapper.querySelector(".strength-track span") : null;
        const label = wrapper ? wrapper.querySelector(".strength-label") : null;

        const updateStrength = () => {
            const value = input.value;
            let score = 0;
            if (value.length >= 12) score += 25;
            if (/[a-z]/.test(value)) score += 15;
            if (/[A-Z]/.test(value)) score += 15;
            if (/\d/.test(value)) score += 15;
            if (/[^A-Za-z0-9]/.test(value)) score += 20;
            if (value.length >= 16) score += 10;

            const clamped = Math.min(score, 100);
            if (track) track.style.setProperty("--strength", `${Math.max(clamped, 8)}%`);
            if (label) {
                if (!value) label.textContent = "Password strength";
                else if (clamped < 50) label.textContent = "Weak";
                else if (clamped < 80) label.textContent = "Good";
                else label.textContent = "Strong";
            }
        };

        input.addEventListener("input", updateStrength);
        updateStrength();
    });

    document.querySelectorAll(".copy-button").forEach((button) => {
        button.addEventListener("click", async () => {
            const input = button.parentElement.querySelector(".copy-source");
            if (!input) return;
            try {
                await navigator.clipboard.writeText(input.value);
                button.textContent = "Copied";
                setTimeout(() => {
                    button.textContent = "Copy";
                }, 1300);
            } catch {
                input.select();
                document.execCommand("copy");
            }
        });
    });

    document.querySelectorAll(".code-input").forEach((input) => {
        input.addEventListener("input", () => {
            input.value = input.value.replace(/\D/g, "").slice(0, 6);
        });
    });
});
