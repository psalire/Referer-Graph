
import ToggleElement from './ToggleElement';

window.addEventListener("graphLoaded", () => {
    var header = document.querySelector('#sidebar .settings-header-label .control-text');
    var btns = new ToggleElement(document.getElementById('buttons'));
    btns.addToggleValue('hide', 'hide-buttons', 'show-buttons');
    document.getElementById('sidebar-toggle').addEventListener('click', function() {
        btns.toggleStyle('hide');
        if (btns.getElem().classList.contains('hide-buttons')) {
            header.textContent = '';
        }
        else {
            header.textContent = 'Controls';
        }
    });
});
