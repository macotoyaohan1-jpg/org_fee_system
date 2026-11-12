
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


    // =========================================
    // SHOW / HIDE PASSWORD
    // =========================================

    if (togglePassword) {

        togglePassword.addEventListener("click", function () {

            if (password.type === "password") {

                password.type = "text";
                togglePassword.textContent = "Hide";

            } else {

                password.type = "password";
                togglePassword.textContent = "Show";

            }

        });

    }


    // =========================================
    // LOGIN FORM VALIDATION
    // =========================================

    loginForm.addEventListener("submit", function (event) {

        const username = document.getElementById("username");
        const captcha = document.getElementById("captcha_answer");

        const loginError = document.getElementById("loginError");

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

        // Let PHP process the login.
        // PHP must still validate every field.

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

                }

            }, 1000);

        }

    }

});
