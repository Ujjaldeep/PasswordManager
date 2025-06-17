/* static/scripts.js */
document.addEventListener('DOMContentLoaded', () => {
    console.log('scripts.js loaded'); // Debug: Confirm script execution

    // Password generation function
    function generatePassword(length = 12) {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&_+.-';
        let password = '';
        for (let i = 0; i < length; i++) {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    }

    // Handle generate password buttons
    const generateButtons = document.querySelectorAll('.generate-btn');
    generateButtons.forEach(button => {
        const form = button.closest('form');
        if (!form) {
            console.error('Generate button not inside a form:', button);
            return;
        }
        const passwordInput = form.querySelector('input[type="password"]');
        if (!passwordInput) {
            console.error('Password input not found in form:', form);
            return;
        }
        button.addEventListener('click', () => {
            passwordInput.value = generatePassword();
            console.log('Generated password for:', passwordInput.id);
            // Clear any existing password error
            const errorSpan = form.querySelector('.password-error');
            if (errorSpan) errorSpan.textContent = '';
            passwordInput.classList.remove('invalid');
        });
    });

    // Handle show password checkboxes in forms
    const showCheckboxes = document.querySelectorAll('.show-password input[type="checkbox"]');
    showCheckboxes.forEach(checkbox => {
        const form = checkbox.closest('form');
        if (!form) {
            console.error('Show password checkbox not inside a form:', checkbox);
            return;
        }
        const passwordInput = form.querySelector('input[type="password"]');
        if (!passwordInput) {
            console.error('Password input not found in form:', form);
            return;
        }
        checkbox.addEventListener('change', () => {
            passwordInput.type = checkbox.checked ? 'text' : 'password';
            console.log('Toggled password visibility for:', passwordInput.id);
        });
    });

    // Handle show password checkboxes in table
    const tableShowCheckboxes = document.querySelectorAll('.show-password-table-checkbox');
    tableShowCheckboxes.forEach(checkbox => {
        const row = checkbox.closest('tr');
        if (!row) {
            console.error('Checkbox not inside a table row:', checkbox);
            return;
        }
        const passwordSpan = row.querySelector('.password-hidden');
        if (!passwordSpan) {
            console.error('Password span not found in row:', row);
            return;
        }
        checkbox.addEventListener('change', () => {
            passwordSpan.textContent = checkbox.checked ? passwordSpan.dataset.password : '********';
            console.log('Toggled table password visibility for index:', checkbox.dataset.index);
        });
    });

    // Validate username and password inputs
    const usernameInputs = document.querySelectorAll('input[name="Username"]');
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    const validUsernameRegex = /^[a-zA-Z0-9_@.]*$/; // Username: letters, numbers, _, @, .
    const validPasswordRegex = /^[A-Za-z0-9!@#$%&_+.\-]*$/; // Password: !@#$%&_+.-, letters, numbers
    const minLength = 6;

    // Username validation
    usernameInputs.forEach(input => {
        const form = input.closest('form');
        const errorSpan = form.querySelector('.username-error') || document.createElement('span');
        errorSpan.className = 'username-error';
        input.parentNode.appendChild(errorSpan);

        input.addEventListener('keypress', (e) => {
            const char = e.key;
            if (!validUsernameRegex.test(char)) {
                e.preventDefault();
                errorSpan.textContent = 'Only letters, numbers, underscores, @, or . allowed';
                input.classList.add('invalid');
                console.log(`Blocked invalid keypress '${char}' in username:`, input.name);
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData('text');
            const sanitizedData = pastedData.replace(/[^a-zA-Z0-9_@.]/g, '');
            input.value = sanitizedData;
            validateUsername(input, errorSpan);
            console.log(`Sanitized pasted username in ${input.name}:`, sanitizedData);
        });

        input.addEventListener('input', () => {
            let value = input.value;
            if (!validUsernameRegex.test(value)) {
                value = value.replace(/[^a-zA-Z0-9_@.]/g, '');
                input.value = value;
                errorSpan.textContent = 'Only letters, numbers, underscores, @, or . allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
            console.log(`Validated username in ${input.name}:`, value);
        });

        input.addEventListener('blur', () => {
            validateUsername(input, errorSpan);
        });

        function validateUsername(input, errorSpan) {
            let value = input.value;
            if (!validUsernameRegex.test(value)) {
                value = value.replace(/[^a-zA-Z0-9_@.]/g, '');
                input.value = value;
                errorSpan.textContent = 'Only letters, numbers, underscores, @, or . allowed';
                input.classList.add('invalid');
            } else {
                errorSpan.textContent = '';
                input.classList.remove('invalid');
            }
        }
    });

    // Password validation
    passwordInputs.forEach(input => {
        const form = input.closest('form');
        const errorSpan = form.querySelector('.password-error');

        input.addEventListener('keypress', (e) => {
            const char = e.key;
            if (char === ' ' || !validPasswordRegex.test(char)) {
                e.preventDefault();
                if (errorSpan) {
                    errorSpan.textContent = char === ' ' ? 'Spaces are not allowed in passwords' : 'Only !@#$%&_+.-, alphabets, and numbers allowed';
                }
                input.classList.add('invalid');
                console.log(`Blocked invalid keypress '${char}' in:`, input.id);
            }
        });

        input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pastedData = (e.clipboardData || window.clipboardData).getData('text');
            const sanitizedData = pastedData.replace(/[^A-Za-z0-9!@#$%&_+.\-]/g, '').replace(/\s/g, '');
            input.value = sanitizedData;
            validatePassword(input, errorSpan);
            console.log(`Sanitized pasted data in ${input.id}:`, sanitizedData);
        });

        input.addEventListener('input', () => {
            let value = input.value;
            let errorMessage = '';

            if (!validPasswordRegex.test(value) || value.includes(' ')) {
                value = value.replace(/\s/g, '').replace(/[^A-Za-z0-9!@#$%&_+.\-]/g, '');
                input.value = value;
                errorMessage = 'Only !@#$%&_+.-, alphabets, and numbers allowed';
                input.classList.add('invalid');
            } else {
                input.classList.remove('invalid');
            }

            if (value.length < minLength && value.length > 0) {
                errorMessage = `Password must be at least ${minLength} characters long`;
                input.classList.add('invalid');
            }

            if (errorSpan) errorSpan.textContent = errorMessage;
            if (errorMessage) console.log(`Validation error in ${input.id}: ${errorMessage}`);
        });

        input.addEventListener('blur', () => {
            validatePassword(input, errorSpan);
        });

        form.addEventListener('submit', (e) => {
            if (!validPasswordRegex.test(input.value) || input.value.includes(' ') || input.value.length < minLength) {
                e.preventDefault();
                validatePassword(input, errorSpan);
                console.log(`Blocked form submission due to invalid password in ${input.id}`);
            }
        });

        function validatePassword(input, errorSpan) {
            let value = input.value;
            let errorMessage = '';

            if (!validPasswordRegex.test(value) || value.includes(' ')) {
                value = value.replace(/\s/g, '').replace(/[^A-Za-z0-9!@#$%&_+.\-]/g, '');
                input.value = value;
                errorMessage = 'Only !@#$%&_+.-, alphabets, and numbers allowed';
                input.classList.add('invalid');
            } else if (value.length < minLength && value.length > 0) {
                errorMessage = `Password must be at least ${minLength} characters long`;
                input.classList.add('invalid');
            } else {
                input.classList.remove('invalid');
            }

            if (errorSpan) errorSpan.textContent = errorMessage;
            if (errorMessage) console.log(`Validation error on blur in ${input.id}: ${errorMessage}`);
        }
    });
});