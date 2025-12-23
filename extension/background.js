// Background script for StockEx extension
// Used to handle requests from content scripts and proxy them to the server

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getCredentials') {
        fetchCredentials(request.domain).then(sendResponse);
        return true; // Keep channel open for async response
    }
});

async function fetchCredentials(domain) {
    const data = await chrome.storage.local.get(['token', 'serverUrl']);
    if (!data.token || !data.serverUrl) {
        return { error: 'Not logged in or server URL not set' };
    }

    try {
        // Fetch all passwords and filter by domain on backend or here
        // For simplicity, we fetch all and filter here for now
        const response = await fetch(`${data.serverUrl}/api/v1/passwords`, {
            headers: { 'X-API-Token': data.token }
        });

        const result = await response.json();
        if (result.status !== 'success') {
            return { error: result.message };
        }

        // Search for matching domain in site name
        const matches = result.data.filter(p =>
            p.site.toLowerCase().includes(domain.toLowerCase()) ||
            domain.toLowerCase().includes(p.site.toLowerCase())
        );

        if (matches.length > 0) {
            // Get the first match and decrypt it
            const entry = matches[0];
            const decryptResp = await fetch(`${data.serverUrl}/api/v1/passwords/decrypt`, {
                method: 'POST',
                headers: {
                    'X-API-Token': data.token,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ encrypted_password: entry.encrypted_password })
            });

            const decryptResult = await decryptResp.json();
            if (decryptResult.status === 'success') {
                return {
                    username: entry.username,
                    password: decryptResult.data.password
                };
            }
        }

        return { error: 'No matching credentials found' };
    } catch (err) {
        console.error('Extension fetch error:', err);
        return { error: 'Failed to connect to StockEx server' };
    }
}
