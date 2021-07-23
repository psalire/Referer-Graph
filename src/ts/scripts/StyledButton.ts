
import { createButton } from './createButton';

export default class StyledButton {
    public button: HTMLButtonElement;
    private toggleValues: Map<string,string[]> = new Map();

    constructor(text: string, btnStyle='btn-primary', useInnerHtml=false) {
        this.button = createButton(text, btnStyle, useInnerHtml);
    }

    public addToggleValue(key: string, val1: string, val2: string): void {
        this.toggleValues.set(key, [val1, val2]);
    }
    public toggleStyle(key: string): void {
        var vals = this.toggleValues.get(key);
        if (!vals) return;
        if (this.button.classList.contains(vals[0])) {
            this.button.classList.remove(vals[0]);
            this.button.classList.add(vals[1]);
        }
        else {
            this.button.classList.remove(vals[1]);
            this.button.classList.add(vals[0]);
        }
    }
    public setText(text: string, useInnerHtml=false) {
        if (useInnerHtml) {
            this.button.innerHTML = text;
        }
        else {
            this.button.textContent = text;
        }
    }
}
