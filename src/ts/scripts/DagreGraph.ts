
import Data from './Data';
import iGraph from './iGraph';
import dagreD3 from 'dagre-d3';
import * as d3 from "d3";
import { createButton } from './createButton';

export default class DagreGraph implements iGraph {
    public data: Data;
    private svg?: object;
    private svgInner?: object;
    private svgId: string;
    private dagreGraph?: object;
    private render: object;

    constructor(data: Data, svgId='graph') {
        this.data = data;
        this.svgId = svgId;
        this.render = new dagreD3.render();
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

        this.dagreGraph = new dagreD3.graphlib.Graph({
            directed: true,
            compound: true
        }).setGraph({
            rankdir: 'LR',
            nodesep: '20'
        });
        console.log(JSON.stringify(this.dagreGraph));

        this.svg.call(zoom.transform, d3.zoomIdentity.translate(
            this.getSvgDimensions().x / 2, 20)
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
            console.log('link')
            console.log(JSON.stringify(link));
            var method = link.target.method || link.method || '';
            var sourceId = link.source.id||link.source;
            var targetId = link.target.id||link.target;
            var targetEdge = this.dagreGraph.edge(sourceId, targetId);
            if (targetEdge) {
                console.log('target')
                console.log(JSON.stringify(targetEdge))
                if (!targetEdge.label.includes(method)) {
                    method = targetEdge+'|'+method;
                }
            }
            console.log('method: '+method)
            this.dagreGraph.setEdge(
                sourceId,
                targetId,
                {label: method}
            );
        }

        // Create the renderer
        var zoom = d3.zoom()
            .on("zoom", () => {
                this.svgInner.select('g').attr("transform", d3.event.transform);
            });
        this.svg.call(zoom);
        // Run the renderer. This is what draws the final graph.
        this.dagreGraph.nodes().forEach((v) => {
            console.log(v);
            console.log(this.dagreGraph.node(v))
        })
        this.render(this.svgInner, this.dagreGraph);

        return this;
    }
    public deleteGraph(): void {
        console.log('dagre.deleteGraph()...');
        for (let edge of this.dagreGraph.edges()) {
            this.dagreGraph.removeEdge(edge.v, edge.w);
        }
        for (let node of this.dagreGraph.nodes()) {
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
        var deleteBtn = createButton('Clear Graph');
        deleteBtn.onclick = ()=>{
            this.data.clear();
            this.updateGraph();
        };
        return [deleteBtn];
    }
    private getSvgDimensions(): {[key: string]:number} {
        let dims = document.getElementById(this.svgId).getBoundingClientRect();
        return {'x':dims.width, 'y':dims.height,'xoff':dims.x,'yoff':dims.y};
    }
}
