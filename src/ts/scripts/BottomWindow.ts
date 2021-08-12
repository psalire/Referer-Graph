
export default class BottomWindow {
    private elem: HTMLElement|null;
    private containerElem: HTMLElement|null;
    private reqHeaderContainerElem: HTMLElement|null;
    private resHeaderContainerElem: HTMLElement|null;
    private headerSelectElem: HTMLElement|null;
    private reqHeaders: string[];
    private resHeaders: string[];

    constructor(id='bottom-window', containerId='bottom-window-container') {
        this.elem = document.getElementById(id);
        this.containerElem = document.getElementById(containerId);
        this.reqHeaderContainerElem = document.getElementById('requests');
        this.resHeaderContainerElem = document.getElementById('responses');
        this.headerSelectElem = document.getElementById('headers-select');
    }

    public initListeners(): void {
        window.addEventListener('bottomWindow', (e)=>{
            if (!e || !e.detail) return;
            switch(e.detail.action) {
                case 'close':
                    break;
                case 'highlight':
                    var nodeElem = document.getElementById(e.detail.id).querySelector('rect');
                    if (!nodeElem) return;
                    if (nodeElem.classList.contains('highlight')) {
                        nodeElem.classList.remove('highlight');
                    }
                    else {
                        nodeElem.classList.add('highlight');
                    }
                case 'delete':
                    break;
                case 'info':
                    this.reqHeaders = JSON.parse(atob(e.detail.reqHeaders));
                    this.resHeaders = JSON.parse(atob(e.detail.resHeaders));
                    console.log('req:');
                    console.log(this.reqHeaders)
                    console.log('res:');
                    console.log(this.resHeaders)

                    if (this.headerSelectElem == null) break;
                    this.headerSelectElem.innerHTML = '';
                    for (let i=0; i<this.reqHeaders.length; i++) {
                        let opt = document.createElement('OPTION');
                        opt.value = i;
                        opt.text = i;
                        this.headerSelectElem.appendChild(opt);
                    }
                    this.reqHeaderContainerElem &&
                        (this.reqHeaderContainerElem.textContent = this.reqHeaders.length ? this.reqHeaders[0] : '');
                    this.resHeaderContainerElem &&
                        (this.resHeaderContainerElem.textContent = this.reqHeaders.length ? this.resHeaders[0] : '');
                    this.show(e.detail.id);
                    break;
            }
            document.getElementById(e.detail.id).dispatchEvent(new MouseEvent('click')); // close tooltip
        });
        this.elem && this.elem.querySelector('#ex-button').addEventListener('click', ()=>{
            this.hide();
        });
        this.headerSelectElem && this.headerSelectElem.addEventListener('change', (e)=>{
            var i = e.target.value;
            console.log(i)
            this.reqHeaderContainerElem &&
                (this.reqHeaderContainerElem.textContent = i<this.reqHeaders.length ? this.reqHeaders[i] : '');
            this.resHeaderContainerElem &&
                (this.resHeaderContainerElem.textContent = i<this.resHeaders.length ? this.resHeaders[i] : '');
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
