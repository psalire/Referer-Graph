
export default class BottomWindow {
    private elem: HTMLElement|null;
    private containerElem: HTMLElement|null;
    private reqHeaderContainerElem: HTMLElement|null;
    private resHeaderContainerElem: HTMLElement|null;

    constructor(id='bottom-window', containerId='bottom-window-container') {
        this.elem = document.getElementById(id);
        this.containerElem = document.getElementById(containerId);
        this.reqHeaderContainerElem = document.getElementById('requests');
        this.resHeaderContainerElem = document.getElementById('responses');
        if (!this.elem) return;
        this.elem.querySelector('#ex-button').addEventListener('click', ()=>{
            this.hide();
        });
        window.addEventListener('bottomWindow', (e)=>{
            if (!e || !e.detail) return;
            switch(e.detail.action) {
                case 'close':
                    break;
                case 'delete':
                    break;
                case 'info':
                    var reqHeaders = JSON.parse(atob(e.detail.reqHeaders));
                    var resHeaders = JSON.parse(atob(e.detail.resHeaders));
                    console.log('req:');
                    console.log(reqHeaders)
                    console.log('res:');
                    console.log(resHeaders)
                    this.reqHeaderContainerElem &&
                        (this.reqHeaderContainerElem.textContent = reqHeaders.length ? reqHeaders[0] : '');
                    this.resHeaderContainerElem &&
                        (this.resHeaderContainerElem.textContent = resHeaders.length ? resHeaders[0] : '');
                    this.show(e.detail.id);
                    break;
            }
            document.getElementById(e.detail.id).dispatchEvent(new MouseEvent('click'));
            console.log(e.detail);
        });
    }

    private hide(): void {
        this.elem && this.elem.classList.add('d-none');
    }
    private show(id: string): void {
        if (!this.elem) return;
        document.getElementById('details-header').textContent = `Details: ${atob(id)}`;
        this.elem.classList.remove('d-none');
    }
}
