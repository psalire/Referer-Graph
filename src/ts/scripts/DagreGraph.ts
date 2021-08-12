
import Data from './Data';
import iGraph from './iGraph';
import dagreD3 from 'dagre-d3';
import * as d3 from "d3";
import { Tooltip } from 'bootstrap';
import StyledButton from './StyledButton';

export default class DagreGraph implements iGraph {
    public data: Data;
    private svg?: object;
    private svgInner?: object;
    private svgId: string;
    private dagreGraph?: object;
    private render: object;
    private tooltips: object[];
    private dataMap: Map<string,number>;
    private tooltipSet: Set<string>;

    constructor(data: Data, svgId='graph') {
        this.data = data;
        this.svgId = svgId;
        this.tooltips = [];
        this.dataMap = new Map();
        this.tooltipSet = new Set();
        this.render = new dagreD3.render();
    }

    public createGraph(orientation='LR'): DagreGraph {
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
            rankdir: orientation && ['LR','RL','TB','BT'].includes(orientation) ? orientation : 'LR',
            nodesep: '20',
            ranksep: '20'
        });
        // console.log(JSON.stringify(this.dagreGraph));

        // this.svg.call(zoom.transform, d3.zoomIdentity.translate(
        //     this.getSvgDimensions().x / 2, 20)
        // );

        return this;
    }
    public updateGraph(): DagreGraph {
        console.log('dagre.updateGraph()...');
        var dataNodes = this.data.getNodes();
        if (dataNodes.length==0) {
            return this;
        }

        // Add states to the graph, set labels, and style
        for (let i=0; i<dataNodes.length; i++) {
            let node = dataNodes[i];
            // console.log(JSON.stringify(node));
            this.dagreGraph.setNode(node.id, {label: node.id});
            this.dataMap.set(btoa(node.id), i);
        }
        for (let link of this.data.getLinks()) {
            // console.log('link')
            // console.log(JSON.stringify(link));
            var method = link.target.method || link.method || '';
            var sourceId = link.source.id||link.source;
            var targetId = link.target.id||link.target;

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
        // console.log('------------NODES--------------')
        // this.dagreGraph.nodes().forEach((v) => {
        //     console.log(v);
        //     console.log(this.dagreGraph.node(v))
        // })
        // console.log('------------EDGES--------------')
        // this.dagreGraph.edges().forEach((e) => {
        //     console.log(e);
        //     console.log(this.dagreGraph.edge(e));
        // })
        // console.log('------------END-EDGES--------------')

        // Run the renderer. This is what draws the final graph.
        this.render(this.svgInner, this.dagreGraph);

        // Add bootstrap tooltip
        this.svgInner.selectAll(".node")
            .attr("title", (v) => {
                let dataNode = this.data.getNode(this.dataMap.get(btoa(v)));
                let getOnClickEvent = (action)=>{
                    return "window.dispatchEvent(new CustomEvent('bottomWindow',{detail:{"
                           +`id:'${btoa(v)}',`
                           +`reqHeaders:'${btoa(JSON.stringify(dataNode.reqHeaders))}',`
                           +`resHeaders:'${btoa(JSON.stringify(dataNode.resHeaders))}',`
                           +`action:'${action}'}}))`
                };
                return `<div class="tooltip-buttons">`
                       +`<button class="btn link-info" onclick="${getOnClickEvent('info')}">View Headers</button>`
                       +`<button class="btn link-warning" onclick="${getOnClickEvent('highlight')}">Highlight Node</button>`
                       // +`<button class="btn link-danger" onclick="${getOnClickEvent('delete')}">Delete Node</button>`
                       +`<button class="btn link-secondary" onclick="${getOnClickEvent('close')}">Close</button>`
                       +`</div>`
            })
            .attr("data-bs-toggle", "tooltip")
            .attr("data-bs-html", "true")
            .attr("data-bs-placement", "right")
            .attr("id", (v) => btoa(v))
            .each((v) => {
                if (this.tooltipSet.has(btoa(v))) return;
                this.tooltipSet.add(btoa(v));
                // console.log(btoa(v));
                this.tooltips.push(new Tooltip(document.getElementById(btoa(v)), {
                    container: '#graph-container',
                    placement: 'right',
                    trigger: 'click',
                    html: true,
                    sanitize: false,
                }));
            });

        return this;
    }
    public deleteGraph(): DagreGraph {
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
        this.tooltips.splice(0, this.tooltips.length);
        this.tooltipSet.clear();
        this.dataMap.clear();
        for (let elem of document.body.getElementsByClassName('tooltip')) {
            elem.remove();
        }
        return this;
    }
    public refreshGraph(): DagreGraph {
        var orientationElem = document.getElementById('orientation-select');
        return this.deleteGraph()
                   .createGraph(orientationElem && orientationElem.value)
                   .updateGraph();
    }
    public getControlComponents(): HTMLElement[] {
        var deleteBtn = StyledButton.createButton('Clear Graph');
        deleteBtn.onclick = ()=>{
            this.data.clear();
            this.refreshGraph();
        };

        var refreshBtn = StyledButton.createButton('Refresh Graph');
        refreshBtn.onclick = ()=>{
            this.refreshGraph();
        }

        var orientationSelect = document.createElement('SELECT');
        orientationSelect.id = 'orientation-select';
        orientationSelect.classList.add('form-select');
        orientationSelect.classList.add('p-1');
        for (let val of [['LR','Left to Right'],['TB','Top to Bottom'],['RL','Right to Left'],['BT','Bottom to Top']]) {
            var option = document.createElement('OPTION');
            option.value = val[0];
            option.text = val[1];
            orientationSelect.appendChild(option);
        }
        orientationSelect.addEventListener('change', (e)=> {
            this.refreshGraph(e.target.value);
        });
        var selectLabel = document.createElement('SPAN');
        selectLabel.textContent = 'Orientation';

        return [deleteBtn, refreshBtn, selectLabel, orientationSelect];
    }
    private getSvgDimensions(): {[key: string]:number} {
        let dims = document.getElementById(this.svgId).getBoundingClientRect();
        return {'x':dims.width, 'y':dims.height,'xoff':dims.x,'yoff':dims.y};
    }
}
