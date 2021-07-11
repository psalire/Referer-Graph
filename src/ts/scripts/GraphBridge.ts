
import D3Graph from './D3Graph';
import DagreGraph from './DagreGraph';
import Data from './Data';
import iGraph from './iGraph';

export default class GraphBridge {
    private data: Data = new Data();
    private readonly graphs: Map<string,iGraph> = new Map([
        ['d3-force', new D3Graph(this.data)],
        ['dagre', new DagreGraph(this.data)]
    ]);
    private activeGraph?: iGraph;

    constructor(initialGraph='d3-force') {
        this.setActiveGraph(initialGraph);
    }

    public setActiveGraph(type: string): void {
        this.activeGraph = this.graphs.get(type);
    }
    public getActiveGraph(): iGraph|undefined {
        return this.activeGraph;
    }
}
