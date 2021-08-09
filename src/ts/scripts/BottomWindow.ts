
export default class BottomWindow {
    private elem: HTMLElement|null;
    private textElem: HTMLElement|null;

    constructor(id='bottom-window', textId='bottom-window-text') {
        this.elem = document.getElementById(id);
        this.textElem = document.getElementById(textId);
        if (!this.elem) return;
        this.elem.querySelector('#ex-button').addEventListener('click', ()=>{
            this.hide();
        });
        window.addEventListener('bottomWindow', (e)=>{
            console.log(e.detail);
            this.show(e.detail.id);
        });
    }

    private hide(): void {
        this.elem && this.elem.classList.add('d-none');
    }
    private show(id: string): void {
        if (!this.elem || !this.textElem) return;
        this.elem.classList.remove('d-none');
        this.textElem.textContent = id;
    }
}
