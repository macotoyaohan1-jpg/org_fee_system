document.addEventListener("DOMContentLoaded", function () {
    const menuToggle = document.getElementById("menuToggle");
    const primaryNavigation = document.getElementById("primaryNavigation");

    if (!menuToggle || !primaryNavigation) {
        return;
    }

    function setMenuOpen(isOpen) {
        menuToggle.setAttribute("aria-expanded", String(isOpen));
        primaryNavigation.classList.toggle("is-open", isOpen);
    }

    menuToggle.addEventListener("click", function () {
        const isOpen = menuToggle.getAttribute("aria-expanded") === "true";
        setMenuOpen(!isOpen);
    });

    // Close the mobile menu after navigating to the shared login or registration page.
    primaryNavigation.addEventListener("click", function (event) {
        if (event.target.closest("a")) {
            setMenuOpen(false);
        }
    });

    document.addEventListener("keydown", function (event) {
        if (event.key === "Escape") {
            setMenuOpen(false);
        }
    });

    window.addEventListener("resize", function () {
        if (window.matchMedia("(min-width: 761px)").matches) {
            setMenuOpen(false);
        }
    });
});
