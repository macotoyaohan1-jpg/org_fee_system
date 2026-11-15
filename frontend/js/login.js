
// =========================================
// LOGIN FORM
// =========================================

document.addEventListener("DOMContentLoaded", function () {

    const loginForm = document.getElementById("loginForm");

    if (!loginForm) {
        return;
    }

    const password = document.getElementById("password");
    const togglePassword = document.getElementById("togglePassword");

    const loginButton = document.getElementById("loginButton");
    const captcha = document.getElementById("captcha_answer");
    const captchaImage = document.getElementById("loginCaptchaImage");
    const refreshCaptcha = document.getElementById("refreshCaptcha");
    const loginError = document.getElementById("loginError");
    const forgotPasswordAction = document.getElementById("forgotPasswordAction");
    const loginIdentifier = document.getElementById("username");
    const registrationLink = document.getElementById("registrationLink");

    if (forgotPasswordAction && loginIdentifier) {
        const failedIdentifier = (forgotPasswordAction.dataset.attemptIdentifier || "").trim().toLowerCase();
        loginIdentifier.addEventListener("input", function () {
            forgotPasswordAction.hidden =
                loginIdentifier.value.trim().toLowerCase() !== failedIdentifier;
        });
    }

    if (registrationLink && registrationLink.getAttribute("aria-disabled") === "true") {
        registrationLink.addEventListener("click", function (event) {
            event.preventDefault();
        });
    }

    function refreshCaptchaImage() {
        captcha.value = "";
        captchaImage.src = "captcha.image.php?refresh=" + Date.now();
    }

    refreshCaptcha.addEventListener("click", refreshCaptchaImage);


    // =========================================
    // SHOW / HIDE PASSWORD
    // =========================================

    if (togglePassword) {

        togglePassword.addEventListener("click", function () {

            const shouldShowPassword = password.type === "password";
            password.type = shouldShowPassword ? "text" : "password";
            togglePassword.classList.toggle("is-visible", shouldShowPassword);
            togglePassword.setAttribute("aria-pressed", String(shouldShowPassword));
            togglePassword.setAttribute(
                "aria-label",
                shouldShowPassword ? "Hide password" : "Show password"
            );

        });

    }


    // =========================================
    // LOGIN FORM VALIDATION
    // =========================================

    loginForm.addEventListener("submit", async function (event) {

        const username = document.getElementById("username");

        loginError.textContent = "";

        if (username.value.trim() === "") {

            event.preventDefault();

            loginError.textContent = "Please enter your username.";

            username.focus();

            return;
        }

        if (password.value === "") {

            event.preventDefault();

            loginError.textContent = "Please enter your password.";

            password.focus();

            return;
        }

        if (captcha.value.trim() === "") {

            event.preventDefault();

            loginError.textContent = "Please answer the CAPTCHA.";

            captcha.focus();

            return;
        }

        event.preventDefault();
        loginButton.disabled = true;
        refreshCaptcha.disabled = true;
        captcha.disabled = true;

        try {
            const response = await fetch("backend/verify_captcha.php", {
                method: "POST",
                headers: {
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                },
                body: new URLSearchParams({
                    csrf_token: document.getElementById("csrfToken").value,
                    captcha_answer: captcha.value.trim()
                })
            });
            const result = await response.json();

            if (!response.ok || !result.valid) {
                loginError.textContent = result.message || "The CAPTCHA answer was incorrect.";
                captcha.value = "";
                refreshCaptchaImage();
                captcha.focus();
                return;
            }

            HTMLFormElement.prototype.submit.call(loginForm);
        } catch (error) {
            loginError.textContent = "Unable to verify CAPTCHA. Please refresh the challenge and try again.";
            refreshCaptchaImage();
        } finally {
            loginButton.disabled = false;
            refreshCaptcha.disabled = false;
            captcha.disabled = false;
        }

    });


    // =========================================
    // LOCKOUT COUNTDOWN DISPLAY
    // =========================================

    const lockoutStatus = document.getElementById("lockoutStatus");
    const lockoutCountdown = document.getElementById("lockoutCountdown");

    // PHP should provide the actual remaining lockout seconds.
    // Example: <span id="lockoutCountdown" data-seconds="19"></span>

    if (lockoutCountdown) {

        let remainingSeconds = Number(lockoutCountdown.dataset.seconds) || 0;

        if (remainingSeconds > 0) {

            lockoutStatus.hidden = false;
            loginButton.disabled = true;

            const countdown = setInterval(function () {

                remainingSeconds--;

                lockoutCountdown.textContent = remainingSeconds;

                if (remainingSeconds <= 0) {

                    clearInterval(countdown);

                    lockoutStatus.hidden = true;
                    loginButton.disabled = false;

                    if (registrationLink) {
                        registrationLink.removeAttribute("aria-disabled");
                        registrationLink.removeAttribute("tabindex");
                        registrationLink.href = "register.php";
                    }

                }

            }, 1000);

        }

    }

});
