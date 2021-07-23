
export function createButton(text: string, btnStyle='btn-primary', useInnerHtml=false): HTMLButtonElement {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `btn ${btnStyle} mb-1 graph-controls-btn`;
    if (useInnerHtml) {
        btn.innerHTML = text;
    }
    else {
        btn.textContent = text;
    }
    return btn;
}
