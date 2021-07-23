
export default class ToggleElement {
    public elem?: HTMLElement;
    private toggleValues: Map<string,string[]> = new Map();

    constructor(elem?: HTMLElement) {
        this.elem = elem;
    }
    public addToggleValue(key: string, val1: string, val2: string): ToggleElement {
        this.toggleValues.set(key, [val1, val2]);
        return this;
    }
    public toggleStyle(key: string): ToggleElement {
        var vals = this.toggleValues.get(key);
        if (!vals || !this.elem) return this;
        if (this.elem.classList.contains(vals[0])) {
            this.elem.classList.remove(vals[0]);
            this.elem.classList.add(vals[1]);
        }
        else if (this.elem.classList.contains(vals[1])) {
            this.elem.classList.remove(vals[1]);
            this.elem.classList.add(vals[0]);
        }
        return this;
    }
    public setElem(elem: HTMLElement): ToggleElement {
        this.elem = elem;
        return this;
    }
    public getElem(): HTMLElement|undefined {
        return this.elem;
    }
}
