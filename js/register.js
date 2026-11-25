
// =========================================
// REGISTRATION FORM
// =========================================

document.addEventListener("DOMContentLoaded", function () {

    const registerForm = document.getElementById("registerForm");

    if (!registerForm) {
        return;
    }

    // Disable browser popup validation.
    // We will display our own messages below the fields.
    registerForm.noValidate = true;
    registerForm.querySelectorAll("input, select, textarea").forEach(function (field) {
        field.setAttribute("autocomplete", "off");
    });

    const registrationDraftKey = "org_fee_registration_draft";
    const excludedDraftFields = new Set([
        "password",
        "confirm_password",
        "captcha_answer",
        "csrf_token",
        "website"
    ]);

    function saveRegistrationDraft() {
        const draft = {};

        registerForm.querySelectorAll("input, select, textarea").forEach(function (field) {
            if (!field.name || excludedDraftFields.has(field.name)) {
                return;
            }

            if (field.type === "checkbox") {
                draft[field.name] = field.checked;
            } else if (field.type === "radio") {
                if (field.checked) draft[field.name] = field.value;
            } else if (field.name.endsWith("[]")) {
                if (!Array.isArray(draft[field.name])) {
                    draft[field.name] = [];
                }
                draft[field.name].push(field.value);
            } else {
                draft[field.name] = field.value;
            }
        });

        try {
            sessionStorage.setItem(registrationDraftKey, JSON.stringify(draft));
        } catch (error) {
            // The form remains usable if browser storage is unavailable.
        }
    }

    function restoreRegistrationDraft() {
        try {
            const draft = JSON.parse(sessionStorage.getItem(registrationDraftKey) || "{}");
            if (!draft || typeof draft !== "object") return;

            registerForm.querySelectorAll("input, select, textarea").forEach(function (field) {
                if (!field.name || excludedDraftFields.has(field.name)) {
                    return;
                }

                if (field.type === "checkbox") {
                    if (typeof draft[field.name] === "boolean") {
                        field.checked = draft[field.name];
                    }
                } else if (field.type === "radio") {
                    if (draft[field.name] === field.value) field.checked = true;
                } else if (field.name.endsWith("[]")) {
                    const values = draft[field.name];
                    if (Array.isArray(values) && field.name === "security_answers[]") {
                        const answerFields = registerForm.querySelectorAll(
                            'input[name="security_answers[]"]'
                        );
                        const answerIndex = Array.from(answerFields).indexOf(field);
                        if (answerIndex >= 0 && values[answerIndex] !== undefined) {
                            field.value = values[answerIndex];
                        }
                    }
                } else if (field.value === "" && draft[field.name] !== undefined) {
                    field.value = draft[field.name];
                }
            });
        } catch (error) {
            // Ignore invalid or unavailable browser draft storage.
        }
    }

    registerForm.addEventListener("input", saveRegistrationDraft);
    registerForm.addEventListener("change", saveRegistrationDraft);
    restoreRegistrationDraft();

    const registrationError = document.getElementById("registrationError");

    if (registrationError) {
        const dismissRegistrationError = function () {
            registrationError.hidden = true;
        };

        registerForm.addEventListener("input", dismissRegistrationError, { once: true });
        registerForm.addEventListener("change", dismissRegistrationError, { once: true });
    }

    const birthdate = document.getElementById("birthdate");
    const age = document.getElementById("age");

    const password = document.getElementById("password");
    const confirmPassword = document.getElementById("confirm_password");

    const extension = document.getElementById("extension");
    const otherExtensionField = document.getElementById("otherExtensionField");

    const strengthText = document.getElementById("strengthText");
    const strengthFill = document.getElementById("strengthFill");


    // =========================================
    // INLINE VALIDATION MESSAGES
    // =========================================

    function getErrorElement(field) {

        if (field.id) {

            const existingError = document.getElementById(field.id + "Error");

            if (existingError) {
                return existingError;
            }

        }

        const fieldContainer = field.closest(".field");

        if (!fieldContainer) {
            return null;
        }

        let error = fieldContainer.querySelector(
            ".custom-field-error"
        );

        if (!error) {

            error = document.createElement("small");

            error.className = "error-message custom-field-error";
            error.setAttribute("role", "alert");

            fieldContainer.appendChild(error);

        }

        return error;
    }


    function showFieldError(field, message) {

        const error = getErrorElement(field);

        field.setAttribute("aria-invalid", "true");

        if (error) {
            error.textContent = message;
            error.hidden = false;
        }

    }


    function clearFieldError(field) {

        const error = getErrorElement(field);

        field.removeAttribute("aria-invalid");

        if (error) {
            error.textContent = "";
        }

        field.setCustomValidity("");

    }

    let serverErrorField = null;
    try {
        const serverErrors = JSON.parse(registerForm.dataset.registrationErrors || "{}");
        Object.entries(serverErrors).forEach(function ([fieldId, message]) {
            const field = document.getElementById(fieldId);
            if (field && typeof message === "string") {
                showFieldError(field, message);
                if (!serverErrorField) {
                    serverErrorField = field;
                }
            }
        });
    } catch (error) {
        console.error("Could not display registration field errors.", error);
    }


    function getValidationMessage(field) {

        if (field.validity.valueMissing) {

            const label = registerForm.querySelector(
                'label[for="' + field.id + '"]'
            );

            let fieldName = label
                ? label.textContent.replace("*", "").trim()
                : "This field";

            if (field.type === "checkbox") {
                // Use the exact consent error required by the handout.
                return "You must agree to the Privacy Notice to register.";
            }

            const requiredAddressMessages = {
                street: "Purok / Street is required.",
                barangay: "Barangay is required.",
                city: "Municipality / City is required.",
                province: "Province is required.",
                country: "Country is required.",
                zip_code: "ZIP Code is required."
            };

            if (requiredAddressMessages[field.id]) {
                return requiredAddressMessages[field.id];
            }

            if (field.tagName === "SELECT") {
                return "Please select " + fieldName.toLowerCase() + ".";
            }

            // Identify the specific required field so the user knows what to fill in.
            return "Please enter your " + fieldName + ".";
        }

        if (field.validity.typeMismatch) {

            if (field.type === "email") {
                return "Please enter a valid email address.";
            }

            return "Please enter a valid value.";
        }

        if (field.validity.patternMismatch) {

            if (field.id === "id_number") {
                return "ID Number must follow the format xxxx-xxxx.";
            }

            if (field.id === "zip_code") {
                return "Please enter a valid 4-digit ZIP code.";
            }

            if (field.id === "organization_contact_number") {
                return "Organization Contact Number must be 11 digits and start with 09.";
            }

            if (field.id === "username") {
                return "Username must start with a letter and contain 8-19 letters and numbers only.";
            }

            if (["first_name", "middle_name", "family_name"].includes(field.id)) {
                const name = field.value.trim();
                const label = field.id === "first_name"
                    ? "First Name"
                    : (field.id === "middle_name" ? "Middle Name" : "Family Name");

                if (field.validity.tooShort) {
                    return label + " must be at least 2 characters.";
                }
                if (name.includes("  ")) {
                    return "Double space is not allowed.";
                }
                if (/([A-Za-z])\1\1/i.test(name)) {
                    return "Three consecutive identical letters are not allowed.";
                }
                if (/^[A-Z ]+$/.test(name)) {
                    return "Do not use all capital letters.";
                }
                if (/[0-9]/.test(name)) {
                    return "Numbers are not allowed in " + label + ".";
                }
                if (!/^[A-Za-z ]+$/.test(name)) {
                    return "Special characters are not allowed in " + label + ".";
                }
                if (field.id === "first_name" && /^[a-z]/.test(name)) {
                    return "First letter of your name must be capital.";
                }
                // The handout requires every word to start uppercase, with the rest lowercase.
                return "First letter of each word must be capital; the rest must be lowercase.";
            }

            if (["barangay", "city", "province", "country"].includes(field.id)) {
                const addressLabels = {
                    barangay: "Barangay",
                    city: "Municipality / City",
                    province: "Province",
                    country: "Country"
                };
                const address = field.value.trim();
                const label = addressLabels[field.id];

                if (address.includes("  ")) {
                    return "Double space is not allowed in " + label + ".";
                }
                if (!/^[A-Za-z]+(?: [A-Za-z]+)*$/.test(address)) {
                    return label + " must contain letters and single spaces only.";
                }
                if (!/^[A-Z][a-z]*(?: [A-Z][a-z]*)*$/.test(address)) {
                    return "First letter of each word in " + label + " must be capital.";
                }
            }

            if (field.id === "street") {
                if (field.value.trim() && /^[a-z]/.test(field.value.trim())) {
                    return "First letter of Purok / Street must be capital.";
                }
                return "Purok / Street must contain letters, numbers, and single spaces only.";
            }

            if (field.id && field.id.startsWith("answer")) {
                return "Security answers must contain letters and single spaces only.";
            }

            if (field.id === "captcha_answer") {
                return "Please enter the 6-character CAPTCHA code.";
            }

            return "Please follow the required format.";
        }

        if (field.validity.tooShort) {
            return "Please enter at least " + field.minLength + " characters.";
        }

        if (field.validity.tooLong) {
            return "Please enter no more than " + field.maxLength + " characters.";
        }

        if (field.validity.rangeUnderflow || field.validity.rangeOverflow) {
            return "Please enter a value within the allowed range.";
        }

        if (field.validity.customError) {
            return field.validationMessage;
        }

        return "Please check this field.";
    }


    // =========================================
    // CALCULATE AGE
    // =========================================

    function calculateAge() {

        if (!birthdate.value) {
            age.value = "";
            return;
        }

        const birth = new Date(birthdate.value + "T00:00:00");
        const today = new Date();

        let calculatedAge = today.getFullYear() - birth.getFullYear();

        const monthDifference = today.getMonth() - birth.getMonth();

        if (
            monthDifference < 0 ||
            (monthDifference === 0 && today.getDate() < birth.getDate())
        ) {
            calculatedAge--;
        }

        if (birth > today || calculatedAge < 0) {
            age.value = "";
            return;
        }

        age.value = calculatedAge;
    }

    function updateAgeFeedback() {
        calculateAge();
        clearFieldError(birthdate);
        clearFieldError(age);

        if (birthdate.value && age.value && Number(age.value) < 18) {
            showFieldError(
                age,
                "You must be at least 18 years old to register."
            );
        }
    }

    birthdate.addEventListener("input", updateAgeFeedback);
    birthdate.addEventListener("change", updateAgeFeedback);

    updateAgeFeedback();

    // =========================================
    // CUSTOM PHILIPPINE ADDRESS SUGGESTIONS
    // =========================================

    const countryInput = document.getElementById("country");
    const provinceInput = document.getElementById("province");
    const cityInput = document.getElementById("city");
    const barangayInput = document.getElementById("barangay");
    const countrySuggestions = document.getElementById("countrySuggestions");
    const provinceSuggestions = document.getElementById("provinceSuggestions");
    const citySuggestions = document.getElementById("citySuggestions");
    const barangaySuggestions = document.getElementById("barangaySuggestions");

    let provinceRecords = [];
    let cityRecords = [];

    function titleCaseAddress(value) {
        return String(value)
            .trim()
            .toLowerCase()
            .replace(/\b[a-z]/g, function (letter) {
                return letter.toUpperCase();
            });
    }

    function closeAddressSuggestions() {
        [
            countrySuggestions,
            provinceSuggestions,
            citySuggestions,
            barangaySuggestions
        ].forEach(function (container) {
            if (container) container.hidden = true;
        });
    }

    function fillAddressSuggestions(container, input, values) {
        container.replaceChildren();

        values.map(titleCaseAddress).forEach(function (value) {
            const option = document.createElement("button");
            option.type = "button";
            option.className = "address-suggestion-option";
            option.textContent = value;

            option.addEventListener("mousedown", function (event) {
                event.preventDefault();
            });

            option.addEventListener("click", function () {
                input.value = value;
                input.dispatchEvent(new Event("input", { bubbles: true }));
                input.dispatchEvent(new Event("change", { bubbles: true }));
                closeAddressSuggestions();
                input.focus();
            });

            container.appendChild(option);
        });

        container.hidden = true;
    }

    function showAddressSuggestions(container, input) {
        const query = input.value.trim().toLowerCase();
        let visibleCount = 0;

        Array.from(container.querySelectorAll("button")).forEach(function (option) {
            const matches = query === "" ||
                option.textContent.toLowerCase().includes(query);
            option.hidden = !matches;
            if (matches) visibleCount++;
        });

        container.hidden = visibleCount === 0;
    }

    function setupAddressSuggestions(input, container, isEnabled) {
        if (!input || !container) return;

        input.addEventListener("focus", function () {
            if (isEnabled && isEnabled()) {
                showAddressSuggestions(container, input);
            } else {
                container.hidden = true;
            }
        });

        input.addEventListener("input", function () {
            if (isEnabled && isEnabled()) {
                showAddressSuggestions(container, input);
            } else {
                container.hidden = true;
            }
        });

        input.addEventListener("keydown", function (event) {
            if (event.key === "Escape") {
                container.hidden = true;
            }
        });
    }

    async function loadProvinceSuggestions() {
        try {
            const response = await fetch(
                "https://psgc.gitlab.io/api/provinces/",
                { headers: { "Accept": "application/json" } }
            );
            if (!response.ok) return;

            provinceRecords = await response.json();
            fillAddressSuggestions(
                provinceSuggestions,
                provinceInput,
                provinceRecords.map(function (province) {
                    return province.name;
                })
            );
            setupAddressSuggestions(
                provinceInput,
                provinceSuggestions,
                function () {
                    return countryInput.value.trim().toLowerCase() === "philippines";
                }
            );
        } catch (error) {
            provinceRecords = [];
        }
    }

    async function loadCitySuggestions() {
        cityInput.value = "";
        barangayInput.value = "";
        cityRecords = [];
        fillAddressSuggestions(citySuggestions, cityInput, []);
        fillAddressSuggestions(barangaySuggestions, barangayInput, []);

        const provinceName = provinceInput.value.trim();
        const provinceRecord = provinceRecords.find(function (province) {
            return titleCaseAddress(province.name).toLowerCase()
                === provinceName.toLowerCase();
        });
        if (!provinceRecord) return;

        try {
            const response = await fetch(
                "https://psgc.gitlab.io/api/provinces/" +
                    provinceRecord.code +
                    "/cities-municipalities/",
                { headers: { "Accept": "application/json" } }
            );
            if (!response.ok) return;

            cityRecords = await response.json();
            fillAddressSuggestions(
                citySuggestions,
                cityInput,
                cityRecords.map(function (city) {
                    return city.name;
                })
            );
            setupAddressSuggestions(
                cityInput,
                citySuggestions,
                function () {
                    return provinceInput.value.trim() !== "";
                }
            );
        } catch (error) {
            cityRecords = [];
        }
    }

    async function loadBarangaySuggestions() {
        barangayInput.value = "";
        fillAddressSuggestions(barangaySuggestions, barangayInput, []);

        const cityName = cityInput.value.trim();
        const cityRecord = cityRecords.find(function (city) {
            return titleCaseAddress(city.name).toLowerCase()
                === cityName.toLowerCase();
        });
        if (!cityRecord) return;

        try {
            const response = await fetch(
                "https://psgc.gitlab.io/api/cities-municipalities/" +
                    cityRecord.code +
                    "/barangays/",
                { headers: { "Accept": "application/json" } }
            );
            if (!response.ok) return;

            const barangays = await response.json();
            fillAddressSuggestions(
                barangaySuggestions,
                barangayInput,
                barangays.map(function (barangay) {
                    return barangay.name;
                })
            );
            setupAddressSuggestions(
                barangayInput,
                barangaySuggestions,
                function () {
                    return cityInput.value.trim() !== "";
                }
            );
        } catch (error) {
            fillAddressSuggestions(barangaySuggestions, barangayInput, []);
        }
    }

    if (provinceInput && cityInput && barangayInput) {
        fillAddressSuggestions(
            countrySuggestions,
            countryInput,
            ["Philippines"]
        );
        setupAddressSuggestions(
            countryInput,
            countrySuggestions,
            function () {
                return true;
            }
        );

        loadProvinceSuggestions();

        provinceInput.addEventListener("change", loadCitySuggestions);
        cityInput.addEventListener("change", loadBarangaySuggestions);
        provinceInput.addEventListener("input", function () {
            cityInput.value = "";
            barangayInput.value = "";
            cityRecords = [];
            fillAddressSuggestions(citySuggestions, cityInput, []);
            fillAddressSuggestions(barangaySuggestions, barangayInput, []);
            const exactProvince = provinceRecords.find(function (province) {
                return titleCaseAddress(province.name).toLowerCase()
                    === provinceInput.value.trim().toLowerCase();
            });
            if (exactProvince) {
                loadCitySuggestions();
            }
        });
        cityInput.addEventListener("input", function () {
            barangayInput.value = "";
            fillAddressSuggestions(barangaySuggestions, barangayInput, []);
            const exactCity = cityRecords.find(function (city) {
                return titleCaseAddress(city.name).toLowerCase()
                    === cityInput.value.trim().toLowerCase();
            });
            if (exactCity) {
                loadBarangaySuggestions();
            }
        });
    }

    document.addEventListener("mousedown", function (event) {
        document.querySelectorAll(".address-suggestions").forEach(function (container) {
            const field = container.closest(".field");
            if (field && !field.contains(event.target)) {
                container.hidden = true;
            }
        });
    });


    const liveAddressFields = [
        document.getElementById("street"),
        document.getElementById("barangay"),
        document.getElementById("city"),
        document.getElementById("province"),
        document.getElementById("country"),
        document.getElementById("zip_code")
    ].filter(function (field) {
        return field !== null;
    });

    liveAddressFields.forEach(function (field) {
        field.addEventListener("input", function () {
            if (!field.value.trim()) {
                clearFieldError(field);
                field.setCustomValidity("");
                return;
            }

            validateField(field);
        });

        field.addEventListener("blur", function () {
            if (!field.value.trim()) {
                if (field.hasAttribute("required")) {
                    showFieldError(field, getValidationMessage(field));
                }
                return;
            }

            validateField(field);
        });
    });


    // =========================================
    // NAME EXTENSION
    // =========================================

    extension.addEventListener("change", function () {

        const otherExtension = document.getElementById("other_extension");

        if (extension.value === "Other") {

            otherExtensionField.hidden = false;
            otherExtension.required = true;

        } else {

            otherExtensionField.hidden = true;
            otherExtension.required = false;
            otherExtension.value = "";

            clearFieldError(otherExtension);

        }

    });

    extension.dispatchEvent(new Event("change"));

    const otherExtension = document.getElementById("other_extension");

    if (otherExtension) {
        otherExtension.addEventListener("input", function () {
            if (!otherExtension.value.trim()) {
                clearFieldError(otherExtension);
                return;
            }

            validateField(otherExtension);
        });

        otherExtension.addEventListener("blur", function () {
            if (!otherExtension.value.trim()) {
                showFieldError(otherExtension, "Enter the name extension you selected.");
                return;
            }

            validateField(otherExtension);
        });
    }

    function setAvailabilityFeedback(feedback, message, state) {
        feedback.textContent = message;
        feedback.className =
            "availability-feedback error-message" +
            (state ? " " + state : "");
    }

    const usernameInput = document.getElementById("username");
    const usernameFeedback = document.getElementById("usernameFeedback");
    let usernameCheckTimer = null;
    let usernameCheckSequence = 0;

    function checkUsernameAvailability() {
        clearTimeout(usernameCheckTimer);
        usernameCheckSequence++;
        const currentSequence = usernameCheckSequence;
        const value = usernameInput.value.trim();

        setAvailabilityFeedback(usernameFeedback, "", "");

        if (value === "") {
            return;
        }

        if (!/^[A-Za-z][A-Za-z0-9]{7,18}$/.test(value)) {
            setAvailabilityFeedback(
                usernameFeedback,
                "Use 8-19 letters and numbers, starting with a letter.",
                "error"
            );
            return;
        }

        setAvailabilityFeedback(usernameFeedback, "Checking username...", "checking");
        usernameCheckTimer = setTimeout(async function () {
            const formData = new URLSearchParams({
                action: "check_username",
                username: value,
                csrf_token: registerForm.querySelector('[name="csrf_token"]').value
            });

            try {
                const response = await fetch("backend/register_process.php", {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                    },
                    body: formData
                });
                const result = await response.json();

                if (currentSequence !== usernameCheckSequence) {
                    return;
                }

                setAvailabilityFeedback(
                    usernameFeedback,
                    result.message || "Unable to check this username.",
                    result.available ? "success" : "error"
                );
            } catch (error) {
                if (currentSequence === usernameCheckSequence) {
                    setAvailabilityFeedback(
                        usernameFeedback,
                        "Username availability could not be checked. Try again.",
                        "error"
                    );
                }
            }
        }, 300);
    }

    usernameInput.addEventListener("input", checkUsernameAvailability);
    usernameInput.addEventListener("blur", checkUsernameAvailability);
    usernameInput.addEventListener("change", checkUsernameAvailability);

    if (usernameInput.value.trim() !== "") {
        window.setTimeout(checkUsernameAvailability, 400);
    }

    const organizationNameInput = document.getElementById("organization_name");
    const organizationNameFeedback = document.getElementById("organizationNameFeedback");
    let organizationNameCheckTimer = null;
    let organizationNameCheckSequence = 0;

    function checkOrganizationNameAvailability() {
        clearTimeout(organizationNameCheckTimer);
        organizationNameCheckSequence++;
        const currentSequence = organizationNameCheckSequence;
        const value = organizationNameInput.value.trim();

        setAvailabilityFeedback(organizationNameFeedback, "", "");

        if (value === "") {
            return;
        }

        if (
            value.length < 2 ||
            value.length > 150 ||
            !/^[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*$/.test(value)
        ) {
            setAvailabilityFeedback(
                organizationNameFeedback,
                "Organization Name must contain 2-150 valid characters.",
                "error"
            );
            return;
        }

        setAvailabilityFeedback(
            organizationNameFeedback,
            "Checking organization name...",
            "checking"
        );

        organizationNameCheckTimer = setTimeout(async function () {
            const formData = new URLSearchParams({
                action: "check_organization_name",
                organization_name: value,
                csrf_token: registerForm.querySelector('[name="csrf_token"]').value
            });

            try {
                const response = await fetch("backend/register_process.php", {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                    },
                    body: formData
                });
                const result = await response.json();

                if (currentSequence !== organizationNameCheckSequence) {
                    return;
                }

                setAvailabilityFeedback(
                    organizationNameFeedback,
                    result.message || "Unable to check this Organization Name.",
                    result.available ? "success" : "error"
                );
            } catch (error) {
                if (currentSequence === organizationNameCheckSequence) {
                    setAvailabilityFeedback(
                        organizationNameFeedback,
                        "Organization Name availability could not be checked.",
                        "error"
                    );
                }
            }
        }, 300);
    }

    if (organizationNameInput && organizationNameFeedback) {
        organizationNameInput.addEventListener("input", checkOrganizationNameAvailability);
        organizationNameInput.addEventListener("blur", checkOrganizationNameAvailability);
        organizationNameInput.addEventListener("change", checkOrganizationNameAvailability);

        if (organizationNameInput.value.trim() !== "") {
            window.setTimeout(checkOrganizationNameAvailability, 400);
        }
    }

    const emailInput = document.getElementById("email");
    const emailFeedback = document.getElementById("emailFeedback");
    let emailCheckTimer = null;
    let emailCheckSequence = 0;

    // Check valid email addresses against the database and display duplicate feedback under the field.
    function checkEmailAvailability() {
        clearTimeout(emailCheckTimer);
        emailCheckSequence++;
        const currentSequence = emailCheckSequence;
        const value = emailInput.value.trim().toLowerCase();

        emailInput.value = value;
        setAvailabilityFeedback(emailFeedback, "", "");

        if (!value) {
            return;
        }

        if (value.length > 100 || !emailInput.validity.valid) {
            setAvailabilityFeedback(
                emailFeedback,
                "Please enter a valid email address.",
                "error"
            );
            return;
        }

        setAvailabilityFeedback(emailFeedback, "Checking email...", "checking");

        const formData = new URLSearchParams({
            action: "check_email",
            email: value,
            csrf_token: registerForm.querySelector('[name="csrf_token"]').value
        });

        emailCheckTimer = setTimeout(async function () {
            try {
                const response = await fetch("backend/register_process.php", {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
                    },
                    body: formData
                });
                const result = await response.json();

                if (currentSequence !== emailCheckSequence) {
                    return;
                }

                setAvailabilityFeedback(
                    emailFeedback,
                    result.message || "Unable to check this email.",
                    result.available ? "success" : "error"
                );
            } catch (error) {
                if (currentSequence === emailCheckSequence) {
                    setAvailabilityFeedback(
                        emailFeedback,
                        "Email availability could not be checked. Try again.",
                        "error"
                    );
                }
            }
        }, 350);
    }

    emailInput.addEventListener("input", checkEmailAvailability);
    emailInput.addEventListener("blur", checkEmailAvailability);
    emailInput.addEventListener("change", checkEmailAvailability);

    // Check a saved or browser-autofilled address even if it did not fire an input event.
    if (emailInput.value.trim() !== "") {
        window.setTimeout(checkEmailAvailability, 400);
    }

    // =========================================
    // PASSWORD VISIBILITY
    // =========================================

    registerForm.querySelectorAll(".password-visibility-toggle").forEach(function (toggle) {

        toggle.addEventListener("click", function () {

            const input = toggle.closest(".password-wrapper")?.querySelector("input");

            if (!input) {
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

    });


    // =========================================
    // REGISTRATION CAPTCHA REFRESH
    // =========================================

    const registrationCaptcha = document.getElementById("registrationCaptcha");

    const refreshRegistrationCaptcha = document.getElementById(
        "refreshRegistrationCaptcha"
    );

    const captchaAnswer = document.getElementById("captcha_answer");

    refreshRegistrationCaptcha.addEventListener("click", function (event) {

        // Refreshing the image must not submit the form or change wizard steps.
        event.preventDefault();
        event.stopPropagation();

        registrationCaptcha.src =
            "registration_captcha.image.php?refresh=" + Date.now();

        captchaAnswer.value = "";

        clearFieldError(captchaAnswer);

    });


    // =========================================
    // PASSWORD STRENGTH
    // =========================================

    function checkPasswordStrength(value) {

        let score = 0;

        if (value.length >= 8) {
            score++;
        }

        if (/[a-z]/.test(value) && /[A-Z]/.test(value)) {
            score++;
        }

        if (/[0-9]/.test(value)) {
            score++;
        }

        if (/[^A-Za-z0-9]/.test(value)) {
            score++;
        }

        if (/[@$!%*?&]/.test(value)) {
            score++;
        }

        if (value.length >= 12) {
            score++;
        }

        if (value.length === 0) {

            strengthText.textContent = "Password strength";
            strengthFill.style.width = "0%";

            return;

        }

        if (score <= 2) {

            strengthText.textContent = "Weak";
            strengthFill.style.width = "33%";
            strengthFill.style.background = "#dc4c5c";

        } else if (score <= 3) {

            strengthText.textContent = "Medium";
            strengthFill.style.width = "66%";
            strengthFill.style.background = "#e6a23c";

        } else {

            strengthText.textContent = "Strong";
            strengthFill.style.width = "100%";
            strengthFill.style.background = "#35a66a";

        }

    }


    password.addEventListener("input", function () {

        checkPasswordStrength(password.value);

        clearFieldError(password);
        clearFieldError(confirmPassword);

    });


    confirmPassword.addEventListener("input", function () {
        clearFieldError(confirmPassword);
    });

    // Prevent duplicate security question selections.
    const questionSelects = [
        document.getElementById("question1"),
        document.getElementById("question2"),
        document.getElementById("question3")
    ];

    function updateQuestionOptions() {
        const selectedValues = questionSelects.map(function (select) {
            return select.value;
        });

        questionSelects.forEach(function (currentSelect) {
            Array.from(currentSelect.options).forEach(function (option) {
                if (option.value === "") {
                    option.disabled = false;
                    return;
                }

                const alreadySelected = selectedValues.includes(option.value);
                option.disabled = alreadySelected && currentSelect.value !== option.value;
            });
        });
    }

    questionSelects.forEach(function (select) {
        select.addEventListener("change", function () {
            updateQuestionOptions();
            clearFieldError(select);
        });
    });

    updateQuestionOptions();


    // =========================================
    // VALIDATE ONE FIELD
    // =========================================

    function validateField(field) {

        clearFieldError(field);

        if (field.disabled || field.closest(".field[hidden]")) {
            return true;
        }

        // Age validation.
        if (field.id === "age") {

            if (!age.value) {
                field.setCustomValidity("Please enter a valid birthdate.");
            } else if (Number(age.value) < 18) {
                field.setCustomValidity("You must be at least 18 years old to register.");
            }

        }

        // Future birthdate validation.
        if (field.id === "birthdate" && birthdate.value) {

            const selectedDate = new Date(birthdate.value + "T00:00:00");

            const today = new Date();
            today.setHours(0, 0, 0, 0);

            if (selectedDate > today) {
                field.setCustomValidity("Birthdate cannot be in the future.");
            }

        }

        // Address and ZIP validation.
        if (field.id === "street" && field.value.trim()) {
            const street = field.value.trim();

            if (street.length < 3 || street.length > 50) {
                field.setCustomValidity(
                    "Purok / Street must be between 3 and 50 characters."
                );
            } else if (street.includes("  ")) {
                field.setCustomValidity("Double space is not allowed in Purok / Street.");
            } else if (!/^[A-Za-z0-9]+(?: [A-Za-z0-9]+)*$/.test(street)) {
                field.setCustomValidity(
                    "Purok / Street must contain letters, numbers, and single spaces only."
                );
            } else if (/^[a-z]/.test(street)) {
                field.setCustomValidity(
                    "First letter of Purok / Street must be capital."
                );
            }
        }

        const addressTitleFields = {
            barangay: "Barangay",
            city: "Municipality / City",
            province: "Province",
            country: "Country"
        };

        if (
            Object.prototype.hasOwnProperty.call(addressTitleFields, field.id) &&
            field.value.trim()
        ) {
            const label = addressTitleFields[field.id];
            const address = field.value.trim();

            if (address.length < 2 || address.length > 50) {
                field.setCustomValidity(label + " must be between 2 and 50 characters.");
            } else if (address.includes("  ")) {
                field.setCustomValidity("Double space is not allowed in " + label + ".");
            } else if (!/^[A-Za-z]+(?: [A-Za-z]+)*$/.test(address)) {
                field.setCustomValidity(label + " must contain letters and single spaces only.");
            } else if (!/^[A-Z][a-z]*(?: [A-Z][a-z]*)*$/.test(address)) {
                field.setCustomValidity(
                    "First letter of each word in " + label + " must be capital."
                );
            }
        }

        if (field.id === "zip_code" && field.value.trim()) {
            if (!/^[0-9]{4}$/.test(field.value.trim())) {
                field.setCustomValidity("ZIP Code must contain exactly 4 digits.");
            }
        }

        if (["first_name", "middle_name", "family_name"].includes(field.id) && field.value.trim()) {
            const label = field.id === "first_name"
                ? "First Name"
                : (field.id === "middle_name" ? "Middle Name" : "Family Name");
            const name = field.value.trim();

            if (name.length < 2) {
                field.setCustomValidity(label + " must be at least 2 characters.");
            } else if (/[0-9]/.test(name)) {
                field.setCustomValidity("Numbers are not allowed in " + label + ".");
            } else if (name.includes("  ")) {
                field.setCustomValidity("Double space is not allowed.");
            } else if (/([A-Za-z])\1\1/i.test(name)) {
                field.setCustomValidity("Three consecutive identical letters are not allowed.");
            } else if (/^[A-Z ]+$/.test(name)) {
                field.setCustomValidity("Do not use all capital letters.");
            } else if (!/^[A-Za-z]+(?: [A-Za-z]+)*$/.test(name)) {
                field.setCustomValidity("Special characters are not allowed in " + label + ".");
            } else if (!/^[A-Z][a-z]+(?: [A-Z][a-z]+)*$/.test(name)) {
                if (field.id === "first_name" && /^[a-z]/.test(name)) {
                    field.setCustomValidity("First letter of your name must be capital.");
                } else {
                    field.setCustomValidity(
                        "First letter of each word must be capital; the rest must be lowercase."
                    );
                }
            }
        }

        if (field.id === "organization_name" && field.value.trim()) {
            const organizationName = field.value.trim();

            if (organizationName.length < 2 || organizationName.length > 150) {
                field.setCustomValidity("Organization Name must be between 2 and 150 characters.");
            } else if (!/^[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*$/.test(organizationName)) {
                field.setCustomValidity("Organization Name contains invalid characters.");
            }
        }

        if (field.id === "organization_acronym" && field.value.trim()) {
            const acronym = field.value.trim();

            if (
                acronym.length < 2 ||
                acronym.length > 30 ||
                !/^[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*$/.test(acronym)
            ) {
                field.setCustomValidity(
                    "Organization Acronym must be 2-30 letters, numbers, spaces, or valid punctuation."
                );
            }
        }

        if (field.id === "department_college" && field.value.trim()) {
            const department = field.value.trim();

            if (
                department.length < 2 ||
                department.length > 150 ||
                !/^[A-Za-z0-9][A-Za-z0-9 .,&()\/\-]*$/.test(department)
            ) {
                field.setCustomValidity(
                    "Department / College must be 2-150 letters, numbers, spaces, or valid punctuation."
                );
            }
        }

        if (field.id === "organization_contact_number" && field.value.trim()) {
            if (!/^09[0-9]{9}$/.test(field.value.trim())) {
                field.setCustomValidity(
                    "Organization Contact Number must be 11 digits and start with 09."
                );
            }
        }

        // Password strength validation.
        if (field.id === "password") {
            const passwordValue = field.value;
            const lengthValid = passwordValue.length >= 8 && passwordValue.length <= 64;
            const compositionValid =
                /[a-z]/.test(passwordValue) &&
                /[A-Z]/.test(passwordValue) &&
                /[0-9]/.test(passwordValue) &&
                /[^A-Za-z0-9\s]/.test(passwordValue);

            if (!lengthValid) {
                field.setCustomValidity("Password must be between 8 and 64 characters.");
            } else if (!compositionValid) {
                field.setCustomValidity(
                    "Password must contain uppercase and lowercase letters, a number, and a special character."
                );
            } else {
                field.setCustomValidity("");
            }

        }

        // Confirm password validation.
        if (field.id === "confirm_password") {

            if (password.value !== confirmPassword.value) {
                field.setCustomValidity("Passwords do not match.");
            }

        }


        // Security answer validation.
        if (field.id && field.id.startsWith("answer")) {

            const answerPattern = /^[A-Za-z]+(?: [A-Za-z]+)*$/;

            if (field.value.trim() && !answerPattern.test(field.value.trim())) {

                field.setCustomValidity(
                    "Security answers must contain letters and single spaces only."
                );

            }

        }

        if (
            ["first_name", "middle_name", "family_name"].includes(field.id) &&
            field.value.trim() &&
            /([A-Za-z])\1\1/i.test(field.value.trim())
        ) {
            field.setCustomValidity(
                "Three consecutive identical letters are not allowed."
            );
        }

        if (
            field.id === "other_extension" &&
            field.value.trim() &&
            !["I", "II", "III", "IV", "IX", "X"].includes(field.value.trim())
        ) {
            field.setCustomValidity(
                "Choose I, II, III, IV, IX, or X for the other name extension."
            );
        }

        if (!field.checkValidity()) {

            showFieldError(field, getValidationMessage(field));

            return false;

        }

        return true;

    }


    // =========================================
    // VALIDATE A GROUP OF FIELDS
    // =========================================

    function validateContainer(container) {

        const fields = Array.from(
            container.querySelectorAll("input, select, textarea")
        );

        // Clear old messages before validating so each field shows only its current error.
        fields.forEach(function (field) {
            clearFieldError(field);
        });

        // Check every field in this step so all missing or invalid fields show their messages together.
        let firstInvalidField = null;
        for (const field of fields) {
            if (!validateField(field)) {
                firstInvalidField = firstInvalidField || field;
            }
        }

        return firstInvalidField;

    }


    // Clear messages when the user edits a field.
    registerForm.addEventListener("input", function (event) {

        if (event.target.matches("input, textarea")) {
            if (!event.target.value.trim()) {
                clearFieldError(event.target);
                return;
            }

            validateField(event.target);
        }

    });

    registerForm.addEventListener("change", function (event) {

        if (event.target.matches("input, select, textarea")) {
            if (!event.target.value.trim()) {
                clearFieldError(event.target);
                return;
            }

            validateField(event.target);
        }

    });


    // =========================================
    // PROGRESSIVE REGISTRATION STEPS
    // =========================================

    const stepHeadings = Array.from(
        registerForm.querySelectorAll(":scope > h2")
    );

    const originalSubmitButton = registerForm.querySelector(
        'button[type="submit"]'
    );

    let currentStepIndex = 0;
    let registrationSteps = [];
    let progressItems = [];

    if (stepHeadings.length > 1 && originalSubmitButton) {

        const progress = document.createElement("ol");

        progress.className = "registration-progress";
        progress.setAttribute("aria-label", "Registration progress");

        const children = Array.from(registerForm.children);

        let activeStep = null;

        children.forEach(function (node) {

            if (node === originalSubmitButton) {
                return;
            }

            if (node.tagName === "H2") {

                activeStep = document.createElement("section");

                activeStep.className = "registration-step";

                activeStep.setAttribute(
                    "aria-labelledby",
                    "registrationStepTitle" + registrationSteps.length
                );

                node.id = "registrationStepTitle" + registrationSteps.length;

                activeStep.appendChild(node);

                registrationSteps.push(activeStep);

                return;

            }

            if (activeStep) {
                activeStep.appendChild(node);
            }

        });


        registrationSteps.forEach(function (step, index) {

            if (step.querySelector("h2")?.textContent.trim() === "Security Questions") {
                step.classList.add("security-question-step");
            }

            const item = document.createElement("li");

            item.textContent = step.querySelector("h2").textContent;
            item.dataset.step = String(index);

            progress.appendChild(item);

            progressItems.push(item);

        });


        const navigation = document.createElement("div");

        navigation.className = "registration-step-navigation";

        navigation.innerHTML =
            '<button type="button" class="secondary-button" id="previousRegistrationStep">Back</button>' +
            '<span class="registration-step-count" id="registrationStepCount"></span>' +
            '<button type="button" class="primary-button" id="nextRegistrationStep">Continue</button>';


        originalSubmitButton.textContent = "Submit Application";

        originalSubmitButton.classList.add(
            "primary-button",
            "registration-submit"
        );


        navigation.appendChild(originalSubmitButton);

        registerForm.appendChild(progress);

        registrationSteps.forEach(function (step) {
            registerForm.appendChild(step);
        });

        registerForm.appendChild(navigation);

        registerForm.classList.add("is-wizard");


        const previousButton = document.getElementById(
            "previousRegistrationStep"
        );

        const nextButton = document.getElementById(
            "nextRegistrationStep"
        );

        const stepCount = document.getElementById(
            "registrationStepCount"
        );


        // Show the selected registration step.
        function showRegistrationStep(index) {

            currentStepIndex = Math.max(
                0,
                Math.min(index, registrationSteps.length - 1)
            );

            registrationSteps.forEach(function (step, stepIndex) {

                step.hidden = stepIndex !== currentStepIndex;

            });

            progressItems.forEach(function (item, stepIndex) {

                item.classList.toggle(
                    "is-current",
                    stepIndex === currentStepIndex
                );

                item.classList.toggle(
                    "is-complete",
                    stepIndex < currentStepIndex
                );

                if (stepIndex === currentStepIndex) {
                    item.setAttribute("aria-current", "step");
                } else {
                    item.removeAttribute("aria-current");
                }

            });

            // Keep the active tab visible in the horizontally scrolling step bar.
            progressItems[currentStepIndex]?.scrollIntoView({
                behavior: "smooth",
                block: "nearest",
                inline: "center"
            });

            previousButton.hidden = currentStepIndex === 0;

            nextButton.hidden =
                currentStepIndex === registrationSteps.length - 1;

            originalSubmitButton.hidden =
                currentStepIndex !== registrationSteps.length - 1;

            stepCount.textContent =
                `Step ${currentStepIndex + 1} of ${registrationSteps.length}`;

            registerForm.querySelector(".form-container")
                ?.scrollIntoView({
                    behavior: "smooth",
                    block: "start"
                });

        }


        // Continue button.
        nextButton.addEventListener("click", function () {

            const invalidField = validateContainer(
                registrationSteps[currentStepIndex]
            );

            if (invalidField) {

                invalidField.focus();

                return;

            }

            showRegistrationStep(currentStepIndex + 1);

        });


        // Back button.
        previousButton.addEventListener("click", function () {

            showRegistrationStep(currentStepIndex - 1);

        });


        // Validate every step before submitting.
        registerForm.addEventListener("submit", async function (event) {

            for (let index = 0; index < registrationSteps.length; index++) {

                const invalidField = validateContainer(
                    registrationSteps[index]
                );

                if (invalidField) {

                    event.preventDefault();

                    showRegistrationStep(index);

                    invalidField.focus();

                    return;

                }

            }

            event.preventDefault();
            const submittedButton = originalSubmitButton;
            submittedButton.disabled = true;

            try {
                const formData = new FormData(registerForm);
                const response = await fetch(registerForm.action, {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                        "X-Requested-With": "XMLHttpRequest"
                    },
                    body: formData,
                    credentials: "same-origin"
                });

                if (response.redirected && response.url) {
                    window.location.assign(response.url);
                    return;
                }

                const result = await response.json();

                if (!response.ok || !result.success) {
                    const field = result.field
                        ? registerForm.querySelector("#" + CSS.escape(result.field))
                        : null;

                    if (field) {
                        showFieldError(field, result.message);
                        const fieldStepIndex = registrationSteps.findIndex(function (step) {
                            return step.contains(field);
                        });
                        if (fieldStepIndex >= 0) {
                            showRegistrationStep(fieldStepIndex);
                        }
                        field.focus();
                    } else {
                        if (registrationError) {
                            registrationError.textContent =
                                result.message || "Registration could not be completed.";
                            registrationError.hidden = false;
                        }
                    }
                }
            } catch (error) {
                if (registrationError) {
                    registrationError.textContent =
                        "Registration could not be completed. Please try again.";
                    registrationError.hidden = false;
                }
            } finally {
                submittedButton.disabled = false;
            }

        });


        const errorStepIndex = serverErrorField
            ? registrationSteps.findIndex(function (step) {
                return step.contains(serverErrorField);
            })
            : -1;

        // Save the current wizard step before leaving for Privacy Notice, so Back restores it.
        const privacyNoticeLink = registerForm.querySelector("#privacyNoticeLink");
        if (privacyNoticeLink) {
            privacyNoticeLink.addEventListener("click", function () {
                saveRegistrationDraft();
                const returnUrl = new URL(window.location.href);
                returnUrl.hash = "registration-step-" + currentStepIndex;
                window.history.replaceState(window.history.state, "", returnUrl.href);
            });
        }

        // Restore the saved wizard step when returning from Privacy Notice.
        const savedStepMatch = window.location.hash.match(/^#registration-step-(\d+)$/);
        const savedStepIndex = savedStepMatch ? Number(savedStepMatch[1]) : 0;
        const startingStepIndex = errorStepIndex >= 0
            ? errorStepIndex
            : Math.min(savedStepIndex, registrationSteps.length - 1);
        showRegistrationStep(startingStepIndex);

        if (serverErrorField) {
            serverErrorField.focus();
        }

    } else {

        // Fallback if the form does not use multiple steps.
        registerForm.addEventListener("submit", function (event) {

            const invalidField = validateContainer(registerForm);

            if (invalidField) {

                event.preventDefault();

                invalidField.focus();

            }

        });

    }

});
