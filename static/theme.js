(function () {
    const root = document.documentElement;
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    const startingTheme = savedTheme || (prefersDark ? 'dark' : 'light');

    function applyTheme(theme) {
        root.dataset.theme = theme;
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            const isDark = theme === 'dark';
            button.setAttribute('aria-pressed', String(isDark));
            button.setAttribute('title', isDark ? 'Switch to light mode' : 'Switch to dark mode');
            button.textContent = isDark ? 'Light' : 'Dark';
        });
    }

    applyTheme(startingTheme);

    document.addEventListener('DOMContentLoaded', function () {
        applyTheme(root.dataset.theme || startingTheme);
        document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
            button.addEventListener('click', function () {
                const nextTheme = root.dataset.theme === 'dark' ? 'light' : 'dark';
                localStorage.setItem('theme', nextTheme);
                applyTheme(nextTheme);
            });
        });
    });
})();
