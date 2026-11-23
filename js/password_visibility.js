document.addEventListener("click", function (event) {
    const target = event.target;
    if (!(target instanceof Element)) {
        return;
    }

    const toggle = target.closest(".password-visibility-toggle");
    const input = toggle?.closest(".password-wrapper")?.querySelector("input");
    if (!toggle || !input) {
        return;
    }

    const shouldShowPassword = input.type === "password";
    input.type = shouldShowPassword ? "text" : "password";
    toggle.classList.toggle("is-visible", shouldShowPassword);
    toggle.setAttribute("aria-pressed", String(shouldShowPassword));
    toggle.setAttribute(
        "aria-label",
        shouldShowPassword ? "Hide password" : "Show password"
    );
});
