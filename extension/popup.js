document.getElementById('login-btn').addEventListener('click', async () => {
    const serverUrl = document.getElementById('server-url').value;
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const status = document.getElementById('status');

    status.innerText = 'Logging in...';

    try {
        const response = await fetch(`${serverUrl}/api/v1/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });

        const result = await response.json();

        if (result.status === 'success') {
            const token = result.data.token;
            await chrome.storage.local.set({ serverUrl, token, username });
            showLoggedIn(username);
            status.innerText = 'Successfully logged in!';
        } else {
            status.innerText = 'Error: ' + result.message;
        }
    } catch (err) {
        status.innerText = 'Error connecting to server';
        console.error(err);
    }
});

document.getElementById('logout-btn').addEventListener('click', async () => {
    await chrome.storage.local.remove(['token', 'username']);
    location.reload();
});

function showLoggedIn(username) {
    document.getElementById('login-form').classList.add('hidden');
    document.getElementById('logged-in-view').classList.remove('hidden');
    document.getElementById('user-display').innerText = username;
}

// Check if already logged in
chrome.storage.local.get(['token', 'username', 'serverUrl'], (data) => {
    if (data.token && data.username) {
        showLoggedIn(data.username);
        if (data.serverUrl) {
            document.getElementById('server-url').value = data.serverUrl;
        }
    }
});
