document.addEventListener("DOMContentLoaded", function () {
    function runCountdown(element, onComplete) {
        if (!element) {
            return;
        }

        let seconds = Number(element.dataset.seconds) || 0;
        if (seconds <= 0) {
            onComplete();
            return;
        }

        const timer = setInterval(function () {
            seconds -= 1;
            element.textContent = String(Math.max(0, seconds));

            if (seconds <= 0) {
                clearInterval(timer);
                onComplete();
            }
        }, 1000);
    }

    const resendButton = document.getElementById("resendOtpButton");
    const resendCountdown = document.getElementById("otpResendCountdown");

    if (resendButton && resendCountdown) {
        runCountdown(resendCountdown, function () {
            resendButton.disabled = false;
        });
    }

    const expiryCountdown = document.getElementById("otpExpiryCountdown");
    if (expiryCountdown) {
        runCountdown(expiryCountdown, function () {
            const form = document.querySelector('form[action="backend/verify_otp.php"]');
            if (form) {
                form.querySelector('button[type="submit"]').disabled = true;
            }
        });
    }
});
