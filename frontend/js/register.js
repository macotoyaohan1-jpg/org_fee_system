
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
                return "Please accept the Privacy Notice before continuing.";
            }

            if (field.tagName === "SELECT") {
                return "Please select " + fieldName.toLowerCase() + ".";
            }

            return "Please enter " + fieldName.toLowerCase() + ".";
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
                return field.id === "first_name"
                    ? "First letter of your name must be capital."
                    : label + " must use title case.";
            }

            if (["barangay", "city", "province", "country"].includes(field.id)) {
                return "Use title-case letters and single spaces only.";
            }

            if (field.id === "street") {
                return "Use letters, numbers, and single spaces only.";
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

    birthdate.addEventListener("change", function () {
        calculateAge();
        clearFieldError(birthdate);
        clearFieldError(age);
    });

    calculateAge();


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

    const usernameInput = document.getElementById("username");
    const usernameFeedback = document.getElementById("usernameFeedback");
    let usernameCheckTimer = null;
    let usernameCheckSequence = 0;

    usernameInput.addEventListener("input", function () {
        clearTimeout(usernameCheckTimer);
        usernameCheckSequence++;
        const currentSequence = usernameCheckSequence;
        const value = usernameInput.value.trim();

        usernameFeedback.textContent = "";
        usernameFeedback.className = "";

        if (value === "") {
            return;
        }

        if (!/^[A-Za-z][A-Za-z0-9]{7,18}$/.test(value)) {
            usernameFeedback.textContent =
                "Use 8-19 letters and numbers, starting with a letter.";
            return;
        }

        usernameFeedback.textContent = "Checking username...";
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

                usernameFeedback.textContent =
                    result.message || "Unable to check this username.";
                usernameFeedback.className = result.available ? "success" : "error";
            } catch (error) {
                if (currentSequence === usernameCheckSequence) {
                    usernameFeedback.textContent =
                        "Username availability could not be checked. Try again.";
                    usernameFeedback.className = "error";
                }
            }
        }, 300);
    });

    document.getElementById("email").addEventListener("blur", function () {
        this.value = this.value.trim().toLowerCase();
    });


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

    refreshRegistrationCaptcha.addEventListener("click", function () {

        registrationCaptcha.src =
            "registration_captcha.image.php?refresh=" + Date.now();

        captchaAnswer.value = "";

        clearFieldError(captchaAnswer);

        captchaAnswer.focus();

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


    // =========================================
    // SECURITY QUESTION DUPLICATES
    // =========================================

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

                option.disabled =
                    alreadySelected && currentSelect.value !== option.value;

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

        // Password strength validation.
        if (field.id === "password") {

            if (
                strengthText.textContent === "Weak" ||
                strengthText.textContent === "Password strength"
            ) {
                field.setCustomValidity("Please create a Medium or Strong password.");
            }

        }

        // Confirm password validation.
        if (field.id === "confirm_password") {

            if (password.value !== confirmPassword.value) {
                field.setCustomValidity("Passwords do not match.");
            }

        }

        // Security question duplicate validation.
        if (questionSelects.includes(field)) {

            const selectedValues = questionSelects.map(function (select) {
                return select.value;
            });

            if (!field.value) {
                field.setCustomValidity("Please select a security question.");
            } else if (
                selectedValues.filter(function (value) {
                    return value === field.value;
                }).length > 1
            ) {
                field.setCustomValidity("Please choose a different security question.");
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
            field.setCustomValidity("Use I, II, III, IV, IX, or X.");
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

        let firstInvalidField = null;

        fields.forEach(function (field) {

            if (!validateField(field) && !firstInvalidField) {
                firstInvalidField = field;
            }

        });

        return firstInvalidField;

    }


    // Clear messages when the user edits a field.
    registerForm.addEventListener("input", function (event) {

        if (event.target.matches("input, textarea")) {
            clearFieldError(event.target);
        }

    });

    registerForm.addEventListener("change", function (event) {

        if (event.target.matches("input, select, textarea")) {
            clearFieldError(event.target);
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
        registerForm.addEventListener("submit", function (event) {

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

        });


        const errorStepIndex = serverErrorField
            ? registrationSteps.findIndex(function (step) {
                return step.contains(serverErrorField);
            })
            : -1;
        showRegistrationStep(errorStepIndex >= 0 ? errorStepIndex : 0);

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
