
// =========================================
// REGISTRATION FORM
// =========================================

document.addEventListener("DOMContentLoaded", function () {

    const registerForm = document.getElementById("registerForm");

    if (!registerForm) {
        return;
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

    birthdate.addEventListener("change", calculateAge);


    // =========================================
    // NAME EXTENSION
    // =========================================

    extension.addEventListener("change", function () {

        if (extension.value === "Other") {
            otherExtensionField.hidden = false;
        } else {
            otherExtensionField.hidden = true;
            document.getElementById("other_extension").value = "";
        }

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
        select.addEventListener("change", updateQuestionOptions);
    });


    // =========================================
    // REGISTRATION VALIDATION
    // =========================================

    registerForm.addEventListener("submit", function (event) {

        let valid = true;

        const errorMessages = document.querySelectorAll(".error-message");

        errorMessages.forEach(function (error) {
            error.textContent = "";
        });

        // Check birthdate and minimum age.
        if (!birthdate.value || Number(age.value) < 18) {

            event.preventDefault();

            alert("You must be at least 18 years old to register.");

            valid = false;
        }

        // Check future birthdate.
        if (birthdate.value) {

            const selectedDate = new Date(birthdate.value + "T00:00:00");
            const today = new Date();

            today.setHours(0, 0, 0, 0);

            if (selectedDate > today) {

                event.preventDefault();

                alert("Birthdate cannot be in the future.");

                valid = false;
            }
        }

        // Check password match.
        if (password.value !== confirmPassword.value) {

            event.preventDefault();

            alert("Passwords do not match.");

            valid = false;
        }

        // Weak passwords are not accepted.
        if (strengthText.textContent === "Weak" ||
            strengthText.textContent === "Password strength") {

            event.preventDefault();

            alert("Please create a Medium or Strong password.");

            valid = false;
        }

        // Check duplicate security questions.
        const selectedQuestions = questionSelects.map(function (select) {
            return select.value;
        });

        if (new Set(selectedQuestions).size !== 3 ||
            selectedQuestions.includes("")) {

            event.preventDefault();

            alert("Please select three different security questions.");

            valid = false;
        }

        // Check security answers.
        for (let i = 1; i <= 3; i++) {

            const answer = document.getElementById("answer" + i);

            const answerPattern = /^[A-Za-z]+(?: [A-Za-z]+)*$/;

            if (!answerPattern.test(answer.value.trim())) {

                event.preventDefault();

                alert("Security answers must contain letters and single spaces only.");

                valid = false;
                break;
            }
        }

        if (!valid) {
            return;
        }

    });

});
