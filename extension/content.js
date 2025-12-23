// Content script for StockEx extension

console.log('StockEx Autofill active');

function findLoginFields() {
    const passwordFields = document.querySelectorAll('input[type="password"]');
    if (passwordFields.length === 0) return null;

    const passwordField = passwordFields[0];
    let userField = null;

    // Try to find a text input before the password field
    const allInputs = Array.from(document.querySelectorAll('input'));
    const pIndex = allInputs.indexOf(passwordField);

    for (let i = pIndex - 1; i >= 0; i--) {
        const input = allInputs[i];
        if (input.type === 'text' || input.type === 'email') {
            userField = input;
            break;
        }
    }

    return { userField, passwordField };
}

async function autofill() {
    const fields = findLoginFields();
    if (!fields) return;

    const domain = window.location.hostname;

    chrome.runtime.sendMessage({ action: 'getCredentials', domain }, (response) => {
        if (response && response.username && response.password) {
            if (fields.userField) {
                fields.userField.value = response.username;
                fields.userField.dispatchEvent(new Event('input', { bubbles: true }));
            }
            fields.passwordField.value = response.password;
            fields.passwordField.dispatchEvent(new Event('input', { bubbles: true }));

            console.log('StockEx: Autofilled credentials for ' + domain);
        }
    });
}

// Run on load and whenever inputs are focused
window.addEventListener('load', () => {
    setTimeout(autofill, 500);
});

// Watch for dynamic form changes or specific triggers could be added here
