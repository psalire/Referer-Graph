
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
        // var graphStyleContainer = document.getElementById('graph-layout-container');

        // for (let btn of graphStyleContainer.getElementsByTagName('button')) {
        //     if (btn.value==initialGraph) {
        //         btn.classList.add('selected-graph');
        //         break;
        //     }
        // }
        // for (let btn of graphStyleContainer.getElementsByTagName('button')) {
        //     btn.onclick = () => {
        //         if (!btn.classList.contains('selected-graph')) {
        //             btn.classList.add('selected-graph');
        //             // graphSelect.value = btn.value;
        //         }
        //     }
        // }
        graphSelect.addEventListener('change', () => {
            // document.getElementById(graphSelect.value+'-btn').click();
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
        var hostsFilterSuccess = document.getElementById('filter-input-success');
        try {
            var filterArr = filter.split(delimeter).filter(v=>v.length>0);
            console.log('Saving filter: ');
            console.log(filterArr);
            this.data.setFilters(filterArr);
            if (!noti) {
                return;
            }
            hostsFilterSuccess.classList.remove('invisible');
            hostsFilterSuccess.classList.add('visible');
            setTimeout(() => {
                hostsFilterSuccess.classList.remove('visible');
                hostsFilterSuccess.classList.add('invisible');
            }, 3000);
        }
        catch(e) {
            if (!noti) {
                return;
            }
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
}
