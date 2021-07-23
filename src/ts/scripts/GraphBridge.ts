
import D3Graph from './D3Graph';
import DagreGraph from './DagreGraph';
import Data from './Data';
import iGraph from './iGraph';

export default class GraphBridge {
    public data: Data = new Data();
    private graphs: Map<string,iGraph> = new Map([
        ['dagre', new DagreGraph(this.data)],
        ['d3-force', new D3Graph(this.data)],
    ]);
    private activeGraph?: iGraph;

    constructor(initialGraph='dagre') {
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
        this.activeGraph.createGraph();
        this.activeGraph.updateGraph();

        var btnContainer = document.getElementById('buttons');
        if (btnContainer) {
            btnContainer.innerHTML = '';
            for (let btn of this.activeGraph.getButtons()) {
                btnContainer.appendChild(btn);
            }
        }
    }
    public getActiveGraph(): iGraph|undefined {
        return this.activeGraph;
    }
    private applyFilter(filter: string, delimeter: string, noti?: boolean): void {
        try {
            var filterArr = filter.split(delimeter).filter(v=>v.length>0);
            console.log('Saving filter: ');
            console.log(filterArr);
            this.data.setFilters(filterArr);
            if (!noti) {
                return;
            }
            this.displayFilterSuccessMessage();
        }
        catch(e) {
            if (!noti) {
                return;
            }
            this.displayFilterErrorMessage();
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
