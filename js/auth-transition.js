(function () {
    const body = document.body;
    if (body.classList.contains("auth-modal-embedded")) {
        return;
    }

    let isSwitching = false;
    const scriptsByPage = {
        login: "js/login.js",
        register: "js/register.js"
    };

    function getPageType(url) {
        if (/(?:^|\/)login\.php$/i.test(url.pathname)) return "login";
        if (/(?:^|\/)register\.php$/i.test(url.pathname)) return "register";
        return null;
    }

    function loadPageScript(pageType, pageDocument, pageUrl) {
        const scriptPath = scriptsByPage[pageType];
        const alreadyLoaded = Array.from(document.scripts).some(function (script) {
            return script.src && new URL(script.src).pathname.endsWith(scriptPath);
        });
        if (alreadyLoaded) return Promise.resolve();

        const source = Array.from(pageDocument.scripts).find(function (script) {
            return script.src && new URL(script.src, pageUrl).pathname.endsWith(scriptPath);
        });
        if (!source) return Promise.resolve();

        return new Promise(function (resolve) {
            const script = document.createElement("script");
            script.src = new URL(source.getAttribute("src"), pageUrl).href;
            script.onload = resolve;
            script.onerror = resolve;
            document.head.appendChild(script);
        });
    }

    function animateCurrentPanels(container, destinationPage) {
        if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
            return Promise.resolve();
        }

        const mobile = window.matchMedia("(max-width: 800px)").matches;
        const elements = mobile
            ? [container]
            : [container.querySelector(".auth-visual"), container.querySelector(".form-panel")];

        return new Promise(function (resolve) {
            let pending = elements.length;
            let resolved = false;
            const finish = function () {
                if (resolved) return;
                resolved = true;
                elements.forEach(function (element) {
                    element.removeEventListener("transitionend", onTransitionEnd);
                });
                resolve();
            };
            const onTransitionEnd = function (event) {
                if (event.target !== event.currentTarget) return;
                pending -= 1;
                if (pending <= 0) finish();
            };

            elements.forEach(function (element) {
                element.addEventListener("transitionend", onTransitionEnd);
            });

            void container.offsetWidth;
            requestAnimationFrame(function () {
                document.documentElement.classList.add(
                    destinationPage === "register"
                        ? "auth-page-slide-to-register"
                        : "auth-page-slide-to-login"
                );
            });
            window.setTimeout(finish, 700);
        });
    }

    async function switchPage(url, destinationPage) {
        if (isSwitching) return;
        isSwitching = true;

        const currentContainer = document.querySelector("body > .auth-container");
        if (!currentContainer) {
            window.location.assign(url.href);
            return;
        }

        const slide = animateCurrentPanels(currentContainer, destinationPage);
        try {
            const response = await fetch(url.href, {
                credentials: "same-origin",
                headers: { "X-Requested-With": "XMLHttpRequest" }
            });
            if (!response.ok) throw new Error("Could not load the destination form.");

            const pageDocument = new DOMParser().parseFromString(
                await response.text(),
                "text/html"
            );
            const nextContainer = pageDocument.querySelector(".auth-container");
            if (!nextContainer) throw new Error("The destination form was not found.");

            await loadPageScript(destinationPage, pageDocument, url);
            await slide;

            const replacement = document.importNode(nextContainer, true);
            document.documentElement.classList.remove(
                "auth-page-slide-to-register",
                "auth-page-slide-to-login"
            );
            currentContainer.replaceWith(replacement);

            body.querySelectorAll(".approval-notice-overlay").forEach(function (notice) {
                notice.remove();
            });
            const notice = pageDocument.querySelector(".approval-notice-overlay");
            if (notice) body.appendChild(document.importNode(notice, true));

            document.title = pageDocument.title;
            history.pushState({ authPage: destinationPage }, "", url.href);
            isSwitching = false;
            document.dispatchEvent(new Event("DOMContentLoaded", { bubbles: true }));
        } catch (error) {
            await slide;
            document.documentElement.classList.remove(
                "auth-page-slide-to-register",
                "auth-page-slide-to-login"
            );
            window.location.assign(url.href);
        }
    }

    document.addEventListener("click", function (event) {
        const link = event.target.closest("#registrationLink[href], .visual-switch-button[href]");
        if (
            !link || event.defaultPrevented || event.button !== 0 || event.metaKey ||
            event.ctrlKey || event.shiftKey || event.altKey || link.target === "_blank"
        ) return;

        const url = new URL(link.href, window.location.href);
        if (url.origin !== window.location.origin) return;
        const destinationPage = getPageType(url);
        if (!destinationPage) return;

        event.preventDefault();
        switchPage(url, destinationPage);
    });

    window.addEventListener("popstate", function () {
        window.location.reload();
    });
})();
