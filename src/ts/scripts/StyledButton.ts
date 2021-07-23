
import ToggleElement from './ToggleElement';
import { createButton } from './createButton';

export default class StyledButton extends ToggleElement  {

    constructor(text: string, btnStyle='btn-primary', useInnerHtml=false) {
        super();
        this.elem = createButton(text, btnStyle, useInnerHtml);
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
