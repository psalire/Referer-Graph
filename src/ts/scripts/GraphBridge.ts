
import D3Graph from './D3Graph';
import DagreGraph from './DagreGraph';
import Data from './Data';
import iGraph from './iGraph';
import LiveUpdateButton from './LiveUpdateButton';
import HighlightNewPathsButton from './HighlightNewPathsButton';
import BottomWindow from './BottomWindow';
import URLFilterForm from './URLFilterForm';

export default class GraphBridge {
    private highlightNewPathsButton: HighlightNewPathsButton = new HighlightNewPathsButton();
    public data: Data = new Data(this.highlightNewPathsButton.getIsHighlightNewPathsOn());
    private graphs: Map<string,iGraph> = new Map([
        ['dagre', new DagreGraph(this.data)],
        ['d3-force', new D3Graph(this.data)],
    ]);
    private activeGraph?: iGraph;
    private isLiveUpdateBtn: LiveUpdateButton;
    private urlFilterForm: URLFilterForm;
    private bottomWindow: BottomWindow;

    constructor(initialGraph='dagre') {
        this.highlightNewPathsButton.getButton().addEventListener('click', ()=>{
            this.data.setIsHighlightNewPaths(this.highlightNewPathsButton.getIsHighlightNewPathsOn());
        });
        this.bottomWindow = new BottomWindow('bottom-window');
        this.bottomWindow.initListeners();

        this.isLiveUpdateBtn = new LiveUpdateButton();
        this.isLiveUpdateBtn.getButton().addEventListener('click', ()=>{
            this.isLiveUpdateBtn.getIsLiveUpdateOn() && this.activeGraph.refreshGraph();
        });

        this.setActiveGraph(initialGraph);
        var graphSelect = document.getElementById('graph-layout-select');
        graphSelect && graphSelect.addEventListener('change', (e) => {
            this.setActiveGraph(e.target.value);
        });

        this.urlFilterForm = new URLFilterForm();
        this.urlFilterForm.getApplyButton().addEventListener('click', ()=>{
            this.applyURLFilter(this.urlFilterForm.getFilterText(), this.urlFilterForm.getFilterDelimeter(), true);
            this.activeGraph.refreshGraph();
        });

        this.applyURLFilter(this.urlFilterForm.getFilterText(), this.urlFilterForm.getFilterDelimeter());
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
            btnContainer.appendChild(this.highlightNewPathsButton.getButton());
            for (let btn of this.activeGraph.getControlComponents()) {
                btnContainer.appendChild(btn);
            }
        }
    }
    public getActiveGraph(): iGraph|undefined {
        return this.activeGraph;
    }
    public getIsLiveUpdateOn(): boolean {
        return this.isLiveUpdateBtn.getIsLiveUpdateOn();
    }
    private applyURLFilter(filter: string, delimeter: string, notify?: boolean): void {
        try {
            var filterArr = filter.split(delimeter).filter(v=>v.length>0);
            console.log('Saving filter: ');
            console.log(filterArr);
            this.data.setFilters(filterArr);
            notify && this.urlFilterForm.displayFilterSuccessMessage();
        }
        catch(e) {
            notify && this.urlFilterForm.displayFilterErrorMessage();
        }
    }
}
