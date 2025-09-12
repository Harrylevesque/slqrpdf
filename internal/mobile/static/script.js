document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('createUserBtn');
    const result = document.getElementById('result');
    btn.addEventListener('click', async function() {
        result.textContent = 'Creating user...';
        try {
            const resp = await fetch('/users/create', { method: 'POST' });
            if (!resp.ok) {
                const text = await resp.text();
                result.textContent = 'Error: ' + text;
                return;
            }
            const data = await resp.json();
            result.textContent = JSON.stringify(data, null, 2);
        } catch (e) {
            result.textContent = 'Network error: ' + e;
        }
    });
});

