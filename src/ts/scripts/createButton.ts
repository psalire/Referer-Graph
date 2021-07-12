
export function createButton(text: string): HTMLButtonElement {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-primary mb-1 graph-controls-btn';
    btn.textContent = text;
    return btn;
}
