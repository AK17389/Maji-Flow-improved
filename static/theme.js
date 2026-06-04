/**
 * theme.js — MAJI-FLOW dark mode manager
 *
 * Handles:
 *  - Applying saved preference on page load (also done inline in base.html
 *    to prevent flash, but this ensures body class is synced too)
 *  - Toggle button behaviour
 *  - Persisting preference to localStorage
 */

(function () {
    const STORAGE_KEY = 'darkMode';
    const DARK_CLASS  = 'dark-mode';

    function isDark() {
        return localStorage.getItem(STORAGE_KEY) === 'enabled';
    }

    function applyTheme(dark) {
        document.documentElement.classList.toggle(DARK_CLASS, dark);
        document.body.classList.toggle(DARK_CLASS, dark);

        const btn = document.getElementById('themeToggle');
        if (btn) {
            const icon = btn.querySelector('.theme-icon');
            if (icon) icon.textContent = dark ? '☽' : '☀';
            btn.setAttribute('title', dark ? 'Switch to light mode' : 'Switch to dark mode');
        }
    }

    function toggle() {
        const going_dark = !isDark();
        localStorage.setItem(STORAGE_KEY, going_dark ? 'enabled' : 'disabled');
        applyTheme(going_dark);
    }

    // Apply on load
    document.addEventListener('DOMContentLoaded', function () {
        applyTheme(isDark());

        const btn = document.getElementById('themeToggle');
        if (btn) btn.addEventListener('click', toggle);
    });
})();
