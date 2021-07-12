
import Data from './Data';
import iGraph from './iGraph';
import dagreD3 from 'dagre-d3';
import * as d3 from "d3";

export default class DagreGraph implements iGraph {
    public data: Data;
    private svg?: object;
    private svgInner?: object;
    private svgId: string;
    private dagreGraph?: object;

    constructor(data: Data, svgId='graph') {
        this.data = data;
        this.svgId = svgId;
    }

    public createGraph(): DagreGraph {
        console.log('dagre.createGraph()...')
        this.svg = d3.select('#graph-container').append('svg').attr('id','graph');
        this.svgInner = this.svg.append('g');

        // Set up zoom support
        var zoom = d3.zoom()
            .on("zoom", () => {
                this.svgInner.select('g').attr("transform", d3.event.transform);
            });
        this.svg.call(zoom);

        this.dagreGraph = new dagreD3.graphlib.Graph().setGraph({
            directed: true,
            compound: true
        });
        var initialScale = 0.75;
        this.svg.call(zoom.transform, d3.zoomIdentity.translate(
            this.getSvgDimensions().x / 2, 20).scale(initialScale)
        );

        return this;
    }
    public updateGraph(): DagreGraph {
        if (this.data.getNodes().length==0) {
            return this;
        }

        // Add states to the graph, set labels, and style
        for (let node of this.data.getNodes()) {
            console.log(JSON.stringify(node));
            this.dagreGraph.setNode(node.id, {label: node.id});
        }
        for (let link of this.data.getLinks()) {
            // this.dagreGraph.setNode(link.source, {label: node.id});
            // this.dagreGraph.setNode(link.target, {label: node.id});
            this.dagreGraph.setEdge(link.source, link.target, {label: link.method});
        }

        // Create the renderer
        var zoom = d3.zoom()
            .on("zoom", () => {
                this.svgInner.select('g').attr("transform", d3.event.transform);
            });
        this.svg.call(zoom);
        // Run the renderer. This is what draws the final graph.
        var render = new dagreD3.render();
        render(this.svgInner, this.dagreGraph);

        return this;
    }
    public deleteGraph(): void {
        console.log('dagre.deleteGraph()...');
        for (let edge of this.dagreGraph.edges()) {
            console.log(edge);
            this.dagreGraph.removeEdge(edge.v, edge.w);
        }
        for (let node of this.dagreGraph.nodes()) {
            console.log(node);
            this.dagreGraph.removeNode(node.id);
        }
        d3.select('#graph-container').select('#graph').remove();
        this.svg = null;
        this.dagreGraph = null;
    }
    public refreshGraph(): DagreGraph {

        return this;
    }
    public getButtons(): HTMLButtonElement[] {

        return [];
    }
    private getSvgDimensions(): {[key: string]:number} {
        let dims = document.getElementById(this.svgId).getBoundingClientRect();
        return {'x':dims.width, 'y':dims.height,'xoff':dims.x,'yoff':dims.y};
    }
}
