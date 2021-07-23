
import D3Graph from './D3Graph';
import DagreGraph from './DagreGraph';
import Data from './Data';
import iGraph from './iGraph';
import { createButton } from './createButton';

export default class GraphBridge {
    public data: Data = new Data();
    private graphs: Map<string,iGraph> = new Map([
        ['dagre', new DagreGraph(this.data)],
        ['d3-force', new D3Graph(this.data)],
    ]);
    private activeGraph?: iGraph;
    private isLiveUpdateOn: boolean;
    private isLiveUpdateBtn: HTMLButtonElement;

    constructor(initialGraph='dagre') {
        this.isLiveUpdateOn = true;
        this.isLiveUpdateBtn = createButton(this.getIsLiveButtonText(), 'btn-success', true);
        this.isLiveUpdateBtn.onclick = ()=>{
            this.isLiveUpdateOn = !this.isLiveUpdateOn;
            if (this.getIsLiveUpdateOn()) {
                this.isLiveUpdateBtn.classList.remove('btn-secondary');
                this.isLiveUpdateBtn.classList.add('btn-success');
            }
            else {
                this.isLiveUpdateBtn.classList.remove('btn-success');
                this.isLiveUpdateBtn.classList.add('btn-secondary');
            }
            this.isLiveUpdateBtn.innerHTML = this.getIsLiveButtonText();
        };

        this.setActiveGraph(initialGraph);
        var graphSelect = document.getElementById('graph-layout-select');

        graphSelect.addEventListener('change', () => {
            this.setActiveGraph(graphSelect.value);
        });

        var hostsFilterBtn = document.getElementById('filter-input-btn');
        var hostsFilterText = document.getElementById('filter-input-text');
        var hostsFilterDelimeter = document.getElementById('filter-input-delimeter');
        var hostsFilterSuccess = document.getElementById('filter-input-success');
        hostsFilterText.value = 'ico,jpg,png,gif,css';
        hostsFilterDelimeter.value = ',';
        hostsFilterBtn.addEventListener('click', () => {
            this.applyFilter(hostsFilterText.value, hostsFilterDelimeter.value, true);
            this.activeGraph.refreshGraph();
        });
        this.applyFilter(hostsFilterText.value, hostsFilterDelimeter.value);
    }

    public setActiveGraph(type: string): void {
        if (this.activeGraph !== undefined) {
            this.activeGraph.deleteGraph();
            let selectedGraph = document.getElementsByClassName('selected-graph')[0];
            selectedGraph && selectedGraph.classList.remove('selected-graph');
        }
        this.activeGraph = this.graphs.get(type);
        this.activeGraph.createGraph()
                        .updateGraph();

        var btnContainer = document.getElementById('buttons');
        if (btnContainer) {
            btnContainer.innerHTML = '';
            console.log(JSON.stringify(this.isLiveUpdateBtn));
            btnContainer.appendChild(this.isLiveUpdateBtn);
            for (let btn of this.activeGraph.getButtons()) {
                btnContainer.appendChild(btn);
            }
        }
    }
    public getActiveGraph(): iGraph|undefined {
        return this.activeGraph;
    }
    public getIsLiveUpdateOn(): boolean {
        return this.isLiveUpdateOn;
    }
    private getIsLiveButtonText(): string {
        return `Live Update: <span class="fw-bold">${this.isLiveUpdateOn?'ON':'OFF'}</span>`;
    }
    private applyFilter(filter: string, delimeter: string, notify?: boolean): void {
        try {
            var filterArr = filter.split(delimeter).filter(v=>v.length>0);
            console.log('Saving filter: ');
            console.log(filterArr);
            this.data.setFilters(filterArr);
            if (notify) {
                this.displayFilterSuccessMessage();
            }
        }
        catch(e) {
            if (notify) {
                this.displayFilterErrorMessage();
            }
        }
    }
    private displayFilterSuccessMessage(): void {
        var hostsFilterSuccess = document.getElementById('filter-input-success');
        hostsFilterSuccess.classList.remove('invisible');
        hostsFilterSuccess.classList.add('visible');
        setTimeout(() => {
            hostsFilterSuccess.classList.remove('visible');
            hostsFilterSuccess.classList.add('invisible');
        }, 3000);
    }
    private displayFilterErrorMessage(): void {
        var hostsFilterSuccess = document.getElementById('filter-input-success');
        hostsFilterSuccess.classList.remove('text-success');
        hostsFilterSuccess.classList.add('text-danger');
        hostsFilterSuccess.textContent = 'Failed';
        hostsFilterSuccess.classList.remove('invisible');
        hostsFilterSuccess.classList.add('visible');
        setTimeout(() => {
            hostsFilterSuccess.classList.remove('visible');
            hostsFilterSuccess.classList.remove('text-danger');
            hostsFilterSuccess.classList.add('invisible');
            hostsFilterSuccess.classList.add('text-success');
            hostsFilterSuccess.textContent = 'Success';
        }, 3000);
    }
}
