
import Data from './Data';
import iGraph from './iGraph';
import dagreD3 from 'dagre-d3';
import * as d3 from "d3";

export default class DagreGraph implements iGraph {
    public data: Data;

    constructor(data: Data) {
        this.data = data;
    }

    public createGraph(): DagreGraph {

        return this;
    }
    public updateGraph(): DagreGraph {

        return this;
    }
    public deleteGraph(): void {

    }
    public refreshGraph(): DagreGraph {

        return this;
    }
}
