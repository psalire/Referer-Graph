
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
}
