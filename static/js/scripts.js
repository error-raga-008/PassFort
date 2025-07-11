// scripts.js: Handles UI interactions for the Password Manager web app.
// Includes AJAX form submissions, password generator, strength checker,
// sidebar navigation, detail panel actions, theme toggling, and error handling.

// ====================
// Main entry: wait until DOM is loaded
// ====================
document.addEventListener('DOMContentLoaded', function() {

    // ====================
    // Password Strength Analyzer Section
    // ====================
    const passwordTestInput = document.getElementById('password-test-input');
    const checkStrengthBtn = document.getElementById('check-strength-btn');
    if (passwordTestInput && checkStrengthBtn) {
        checkStrengthBtn.addEventListener('click', function() {
            const password = passwordTestInput.value;
            const charCount = document.getElementById('char-count');
            const lowerCase = document.getElementById('lower-case');
            const upperCase = document.getElementById('upper-case');
            const numbers = document.getElementById('numbers');
            const symbols = document.getElementById('symbols');
            const strengthDisplay = document.getElementById('strength-display');
            const timeValue = document.getElementById('time-value');

            if (password.length === 0) {
                charCount.textContent = '0';
                lowerCase.classList.remove('active');
                upperCase.classList.remove('active');
                numbers.classList.remove('active');
                symbols.classList.remove('active');
                strengthDisplay.textContent = 'No Password';
                strengthDisplay.className = 'strength-display';
                timeValue.textContent = '0 seconds';
                return;
            }

            fetch('/password-strength', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password: password }),
            })
            .then(response => response.json())
            .then(data => {
                // Update counts and active indicators
                charCount.textContent = data.length;
                data.has_lower
                    ? lowerCase.classList.add('active')
                    : lowerCase.classList.remove('active');
                data.has_upper
                    ? upperCase.classList.add('active')
                    : upperCase.classList.remove('active');
                data.has_number
                    ? numbers.classList.add('active')
                    : numbers.classList.remove('active');
                data.has_symbol
                    ? symbols.classList.add('active')
                    : symbols.classList.remove('active');

                // Determine strength label based on crack time
                const seconds = data.crack_time_sec;
                let strengthText;
                if (seconds === 0) {
                    strengthText = 'No Password';
                } else if (seconds < 1) {
                    strengthText = 'Very Weak';
                } else if (seconds < 60) {
                    strengthText = 'Weak';
                } else if (seconds < 3600) {
                    strengthText = 'Moderate';
                } else if (seconds < 86400) {
                    strengthText = 'Strong';
                } else {
                    strengthText = 'Very Strong';
                }
                strengthDisplay.textContent = strengthText;
                strengthDisplay.className = 'strength-display';
                strengthDisplay.classList.add(
                    strengthText.toLowerCase().replace(/\s+/g, '-')
                );

                // Display crack time
                timeValue.textContent = `${seconds.toFixed(2)} sec`;
            })
            .catch(error => {
                console.error('Error:', error);
            });
        });
    }

    // ====================
    // Password Manager Detail Panel Section
    // ====================
    const detailPanel = document.getElementById('detail-panel');
    const headerName = document.getElementById('detail-header-name');
    const userLabel = document.getElementById('detail-username');
    const passLabel = document.getElementById('detail-password');
    const siteLabel = document.getElementById('detail-website');
    const noteLabel = document.getElementById('detail-note');
    const tbody = document.querySelector('.table-panel table tbody');
    if (tbody) {
        tbody.addEventListener('click', (e) => {
            const row = e.target.closest('tr');
            if (!row) return;
            // ignore clicks on delete button
            if (e.target.closest('button.delete-btn')) return;
            // Remove selection from all rows
            tbody.querySelectorAll('tr').forEach(r => r.classList.remove('selected'));
            // Highlight the clicked row
            row.classList.add('selected');
            // Populate detail panel fields
            headerName.textContent = row.dataset.website;
            userLabel.textContent = row.dataset.username;
            passLabel.textContent = '••••••';
            siteLabel.textContent = row.dataset.website;
            noteLabel.textContent = row.dataset.note;
            // Show the panel
            detailPanel.style.display = 'block';
            // reset reveal controls for new selection
            const showRow = document.querySelector('.show-row');
            showRow.style.display = 'flex';
            keyInput.disabled = false;
            keyInput.value = '';
            showBtn.style.display = 'inline-block';
            copyUsernameBtn.style.display = 'none';
            copyPasswordBtn.style.display = 'none';
            gotoBtn.style.display = 'none';

            // Reset detail panel on row selection
        });
    }

    // ====================
    // Inline Reveal/Copy/GoTo Actions
    // ====================
    const showBtn = document.getElementById('show-password');
    const keyInput = document.getElementById('key-input');
    const copyUsernameBtn = document.getElementById('copy-username');
    const copyPasswordBtn = document.getElementById('copy-password');
    const gotoBtn = document.getElementById('goto-website');
    // Hide action buttons until reveal
    copyUsernameBtn.style.display = 'none';
    copyPasswordBtn.style.display = 'none';
    gotoBtn.style.display = 'none';
    showBtn.addEventListener('click', () => {
        const selected = document.querySelector('tr.selected');
        if (!selected) return;
        const key = keyInput.value;
        const entryId = selected.dataset.id;
        fetch(`/reveal-password/${entryId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ key })
        })
        .then(res => res.json())
        .then(data => {
            if (data.success) {
                // show decrypted password and buttons
                document.getElementById('detail-password').textContent = data.password;
                copyUsernameBtn.style.display = 'inline-block';
                copyPasswordBtn.style.display = 'inline-block';
                gotoBtn.style.display = 'inline-block';
                showBtn.style.display = 'none';
                keyInput.disabled = true;
                // hide key input row after successful reveal
                document.querySelector('.show-row').style.display = 'none';
            } else {
                // show error modal
                document.getElementById('error-modal').style.display = 'flex';
            }
        });
    });
    // Copy actions
    copyUsernameBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(userLabel.textContent);
    });
    copyPasswordBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(document.getElementById('detail-password').textContent);
    });
    // Goto website
    gotoBtn.addEventListener('click', () => {
        const url = siteLabel.textContent;
        window.open(url, '_blank');
    });

    // ====================
    // Error Modal Handlers
    // ====================
    const retryBtn = document.getElementById('retry-key');
    const otpBtn = document.getElementById('otp-key');
    retryBtn?.addEventListener('click', () => {
        // Hide error modal and reset key input
        document.getElementById('error-modal').style.display = 'none';
        keyInput.value = '';
        keyInput.focus();
    });
    otpBtn?.addEventListener('click', () => {
        // Send safety key to user's email via server endpoint
        const selected = document.querySelector('tr.selected');
        if (!selected) return;
        const entryId = selected.dataset.id;
        fetch(`/send-key/${entryId}`, { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    alert('Your safety key has been emailed to you.');
                } else {
                    alert('Unable to send safety key. Please try again later.');
                }
                document.getElementById('error-modal').style.display = 'none';
            })
            .catch(err => {
                console.error('Error sending key:', err);
                alert('Error sending safety key. Please try again later.');
                document.getElementById('error-modal').style.display = 'none';
            });
    });

    // ====================
    // Theme Toggle Logic
    // ====================
    const themeToggle = document.getElementById('theme-toggle');
    // Load stored theme or default to light
    const savedTheme = localStorage.getItem('theme') || 'light';
    if (savedTheme === 'dark' && themeToggle) {
        document.documentElement.setAttribute('data-theme','dark');
        themeToggle.checked = true;
    }
    themeToggle?.addEventListener('change', () => {
        const theme = themeToggle.checked ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('theme', theme);
    });

    // ====================
    // Password Length Slider
    // ====================
    const lengthSlider = document.getElementById('length');
    const lengthValue = document.getElementById('length-value');
    if (lengthSlider && lengthValue) {
        lengthSlider.addEventListener('input', function () {
            lengthValue.textContent = this.value;
        });
    }

    // ====================
    // Refresh and Copy Password Button Handlers
    // ====================
    const copyBtn = document.getElementById('copy-btn');
    const refreshBtn = document.getElementById('refresh-btn');
    const passwordForm = document.getElementById('password-form');
    const passwordOutput = document.getElementById('password-output');
    if (refreshBtn && passwordForm) refreshBtn.addEventListener('click', () => passwordForm.submit());
    if (copyBtn && passwordOutput) copyBtn.addEventListener('click', () => {
        passwordOutput.select(); document.execCommand('copy'); alert('Password copied!');
    });

    // ====================
    // Sidebar collapsible items
    // ====================
    const collapsibles = document.querySelectorAll('.collapsible-header');

    collapsibles.forEach(collapsible => {
        collapsible.addEventListener('click', function() {
            // Toggle collapse icon only
            const icon = this.querySelector('.fa-chevron-down');
            if (icon) {
                icon.style.transform = icon.style.transform === 'rotate(180deg)' ? 'rotate(0deg)' : 'rotate(180deg)';
            }
        });
    });
}); // end DOMContentLoaded