
window.addEventListener("graphLoaded", () => {
    var settingsBtn = document.getElementById('settings-btn');
    settingsBtn.onclick = () => {
        var inner = '<img src="/static/image/gear-fill.svg" alt="Settings Icon"> ';
        if (settingsBtn.textContent.startsWith(' Open')) {
            inner += 'Close Settings';
        }
        else {
            inner += 'Open Settings';
        }
        settingsBtn.innerHTML = inner;
    }
});
