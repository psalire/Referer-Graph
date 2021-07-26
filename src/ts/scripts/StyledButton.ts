
import { Tooltip } from 'bootstrap';
import ToggleElement from './ToggleElement';

export default class StyledButton extends ToggleElement  {

    constructor(text: string, btnStyle='btn-primary', useInnerHtml=false) {
        super();
        this.elem = StyledButton.createButton(text, btnStyle, useInnerHtml);
    }

    public static createButton(text: string, btnStyle='btn-primary', useInnerHtml=false): HTMLButtonElement {
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
    public setText(text: string, useInnerHtml=false) {
        if (!this.elem) return;
        if (useInnerHtml) {
            this.elem.innerHTML = text;
        }
        else {
            this.elem.textContent = text;
        }
    }
    public getButton(): HTMLElement|undefined {
        return this.getElem();
    }
}
