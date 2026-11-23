document.addEventListener("DOMContentLoaded", function () {
    const backButton = document.getElementById("privacyNoticeBack");

    if (!backButton) {
        return;
    }

    // Go back to the registration form in this same page or Home modal.
    backButton.addEventListener("click", function () {
        if (window.history.length > 1) {
            window.history.back();
            return;
        }

        // If opened directly without a previous page, return to the registration form.
        window.location.assign("register.php");
    });
});
