
import D3Graph from './D3Graph';
import DagreGraph from './DagreGraph';
import Data from './Data';
import iGraph from './iGraph';
import StyledButton from './StyledButton';
import ToggleElement from './StyledButton';
import { createButton } from './createButton';

export default class GraphBridge {
    public data: Data = new Data();
    private graphs: Map<string,iGraph> = new Map([
        ['dagre', new DagreGraph(this.data)],
        ['d3-force', new D3Graph(this.data)],
    ]);
    private activeGraph?: iGraph;
    private isLiveUpdateOn: boolean;
    private isLiveUpdateBtn: StyledButton;
    private hostsFilterSuccessElem: ToggleElement;

    constructor(initialGraph='dagre') {
        this.isLiveUpdateOn = true;
        this.isLiveUpdateBtn = new StyledButton(this.createIsLiveButtonText(), 'btn-success', true);
        this.isLiveUpdateBtn.addToggleValue('color', 'btn-success', 'btn-secondary');
        this.isLiveUpdateBtn.getButton().onclick = ()=>{
            this.isLiveUpdateOn = !this.isLiveUpdateOn;
            this.isLiveUpdateBtn.toggleStyle('color');
            this.isLiveUpdateBtn.setText(this.createIsLiveButtonText(), true);
            this.isLiveUpdateOn && this.activeGraph.refreshGraph();
        };

        this.setActiveGraph(initialGraph);
        var graphSelect = document.getElementById('graph-layout-select');
        graphSelect && graphSelect.addEventListener('change', () => {
            this.setActiveGraph(graphSelect.value);
        });

        var hostsFilterBtn = document.getElementById('filter-input-btn');
        var hostsFilterText = document.getElementById('filter-input-text');
        var hostsFilterDelimeter = document.getElementById('filter-input-delimeter');
        hostsFilterText.value = 'ico,jpg,png,gif,css';
        hostsFilterDelimeter.value = ',';
        hostsFilterBtn.addEventListener('click', () => {
            this.applyURLFilter(hostsFilterText.value, hostsFilterDelimeter.value, true);
            this.activeGraph.refreshGraph();
        });

        this.hostsFilterSuccessElem = new ToggleElement(document.getElementById('filter-input-success'));
        this.hostsFilterSuccessElem.addToggleValue('visible', 'visible', 'invisible')
                                   .addToggleValue('color', 'text-success', 'text-danger');

        this.applyURLFilter(hostsFilterText.value, hostsFilterDelimeter.value);
    }

    public setActiveGraph(type: string): void {
        if (this.activeGraph !== undefined) {
            this.activeGraph.deleteGraph();
            let selectedGraph = document.getElementsByClassName('selected-graph')[0];
            selectedGraph && selectedGraph.classList.remove('selected-graph');
        }
        this.activeGraph = this.graphs.get(type);
        this.activeGraph.createGraph().updateGraph();

        var btnContainer = document.getElementById('buttons');
        if (btnContainer) {
            btnContainer.innerHTML = '';
            btnContainer.appendChild(this.isLiveUpdateBtn.getButton());
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
    private createIsLiveButtonText(): string {
        return `Live Update: <span class="fw-bold">${this.getIsLiveUpdateOn()?'ON':'OFF'}</span>`;
    }
    private applyURLFilter(filter: string, delimeter: string, notify?: boolean): void {
        try {
            var filterArr = filter.split(delimeter).filter(v=>v.length>0);
            console.log('Saving filter: ');
            console.log(filterArr);
            this.data.setFilters(filterArr);
            notify && this.displayFilterSuccessMessage();
        }
        catch(e) {
            notify && this.displayFilterErrorMessage();
        }
    }
    private displayFilterSuccessMessage(): void {
        if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
            return;
        }
        this.hostsFilterSuccessElem.setElem(document.getElementById('filter-input-success'))
                                   .toggleStyle('visible');
        setTimeout(() => {
            if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
                this.hostsFilterSuccessElem.toggleStyle('visible');
            }
        }, 3000);
    }
    private displayFilterErrorMessage(): void {
        if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
            return;
        }
        this.hostsFilterSuccessElem.setElem(document.getElementById('filter-input-success'))
                                   .toggleStyle('visible')
                                   .toggleStyle('color');
        this.hostsFilterSuccessElem.getElem().textContent = 'Error';
        setTimeout(() => {
            if (this.hostsFilterSuccessElem.getElem().classList.contains('visible')) {
                this.hostsFilterSuccessElem.toggleStyle('visible')
                                           .toggleStyle('color');
                this.hostsFilterSuccessElem.getElem().textContent = 'Success';
            }
        }, 3000);
    }
}
