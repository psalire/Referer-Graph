
import Data from './Data';
import iGraph from './iGraph';
import StyledButton from './StyledButton';
import * as d3 from "d3";

export default class D3Graph implements iGraph {
    private svg: any;
    private svgId: string;
    private simulation: any;
    public data: Data;
    private isAnimationStopped: boolean = false;
    private readonly simulationStrength = -300;
    private readonly colorScheme = d3.scaleSequential(d3.interpolateRainbow);
    private readonly radius = 18;
    private readonly circleStrokeWidth = 2;
    private readonly font = 'sans-serif';
    private readonly fontSize = '11px';

    constructor(data: Data, svgId='graph') {
        this.data = data;
        this.svgId = svgId;
    }

    public createGraph(): D3Graph {
        console.log('d3graph.createGraph()...')
        this.svg = d3.select('#graph-container').append('svg').attr('id', this.svgId);
        var zoomed = () => {
            this.svg
            .attr("transform", "translate("+d3.event.transform.x+","+d3.event.transform.y + ")"+" scale("+d3.event.transform.k+")");
        };
        this.svg = this.svg.call(d3.zoom().on("zoom", zoomed)).append("g");
        // Define end marker
        this.svg
            .append("defs")
            .append("marker")
            .attr("id", "arrow")
            .attr("viewBox", "0 -5 10 10")
            .attr("refX", this.radius+this.circleStrokeWidth+1)
            .attr("refY", 0)
            .attr("markerWidth", 8)
            .attr("markerHeight", 8)
            .attr("orient", "auto")
            .append("svg:path")
            .attr("d", "M0,-5L10,0L0,5");
        let dims = this.getSvgDimensions();
        this.simulation = d3.forceSimulation()
            .force("link", d3.forceLink().distance((d)=>{
                try {
                    const text = document.getElementById('textPath_'+this.getPathsToId(d)).textContent;
                    const canvas = document.createElement('canvas');
                    const context = canvas.getContext('2d');
                    context.font = `${this.fontSize} ${this.font}`;
                    var length = context.measureText(text+'===').width+(this.radius+this.circleStrokeWidth)*2;
                    d.target.method && (d.method = d.target.method);
                    return length;
                }
                catch(e) {
                    console.error(e);
                    return this.longestLength;
                }
            }).id((d) => { return d.id; }))
            .force("charge", d3.forceManyBody().strength(this.simulationStrength))
            // .force("center", d3.forceCenter(dims.x / 2, dims.y / 2))
            .force("x", d3.forceX(dims.x / 2).strength(0.05))
            .force("y", d3.forceY(dims.y / 2).strength(0.05))
            .force("collision", d3.forceCollide().radius(this.radius+10));

        var dataLinks = this.data.getLinks();
        var dataNodes = this.data.getNodes();

        var link = this.svg.append("g")
            .attr("class", "links")
            .selectAll("line")
            .data(dataLinks);
        link = this.formatLink(link);

        var node = this.svg.append("g")
            .attr("class", "nodes")
            .selectAll("circle")
            .data(dataNodes)
        node = this.formatNode(node);

        var text = this.svg.append("g")
            .attr("class", "labels")
            .enter()
        // this.formatText(text);

        // Update link labels
        var linkPath = this.svg.select('.links')
                        .selectAll('.linkPath')
                        .data(dataLinks);
        linkPath.exit().remove();
        linkPath = this.formatLinkPath(linkPath);

        var linkLabel = this.svg.select('.links')
                            .selectAll('.linkLabel')
                            .data(dataLinks);
        linkLabel.exit().remove();
        linkLabel = this.formatLinkLabel(linkLabel);

        var text = this.svg.select('.labels')
                    .selectAll('.nodeLabel')
                    .data(dataNodes);
        text.exit().remove();
        this.formatText(text).merge(text);
        text = this.svg.select('.labels')
                .selectAll('.nodeLabel')

        this.defineSimulation(dataNodes, dataLinks, link, node, text);

        return this;
    }

    public updateGraph(): D3Graph {
        var dataLinks = this.data.getLinks();
        var dataNodes = this.data.getNodes();
        console.log('links: '+JSON.stringify(dataLinks))
        console.log('nodes: '+JSON.stringify(dataNodes))

        // Update links
        var link = this.svg.select('.links')
                    .selectAll("line")
                    .data(dataLinks);
        // Exit any old links
        link.exit().remove();
        // Enter links
        link = this.formatLink(link).merge(link);

        // Update the nodes
        var node = this.svg.select('.nodes')
        .selectAll("circle").data(dataNodes);
        // Exit any old nodes
        node.exit().remove();
        // Enter any new nodes
        node = this.formatNode(node).merge(node)

        // Update link labels
        var linkPath = this.svg.select('.links')
                        .selectAll('.linkPath')
                        .data(dataLinks);
        linkPath.exit().remove();
        linkPath = this.formatLinkPath(linkPath)
                        .merge(linkPath);

        var linkLabel = this.svg.select('.links')
                            .selectAll('.linkLabel')
                            .data(dataLinks);
        linkLabel.exit().remove();
        linkLabel = this.formatLinkLabel(linkLabel)
                        .merge(linkLabel);

        var text = this.svg.select('.labels')
                    .selectAll('.nodeLabel')
                    .data(dataNodes);
        text.exit().remove();
        this.formatText(text).merge(text);
        text = this.svg.select('.labels')
                .selectAll('.nodeLabel');

        // Redefine and restart simulation
        this.defineSimulation(dataNodes, dataLinks, link, node, text, linkPath, linkLabel);
        this.restartSimulation();

        return this;
    }

    public deleteGraph(): D3Graph {
        console.log('d3graph.deleteGraph()...');
        if (this.svg) {
            this.simulation.stop();
            this.simulation
                .force("link", null)
                .force("charge", null)
                .force("x", null)
                .force("y", null)
                .force("collision", null);
            this.simulation.nodes(this.data.getNodes()).on('tick', null);
            d3.select('#graph-container').select('#'+this.svgId).remove();
            // document.getElementById(this.svgId).remove();
            this.svg = null;
            this.isAnimationStopped = false;
        }
        return this;
    }
    public clearGraph(): D3Graph {
        this.data.clear();
    }
    public refreshGraph(startAnimation=false): D3Graph {
        startAnimation && (this.isAnimationStopped = false);
        return this.updateGraph();
    }
    public stopAnimation(): D3Graph {
        this.simulation.stop();
        this.isAnimationStopped = true;
        return this;
    }

    public getControlComponents(): HTMLElement[] {
        var deleteBtn = StyledButton.createButton('Clear Graph');
        deleteBtn.onclick = ()=>{
            this.data.clear();
            this.refreshGraph();
        };
        var stopBtn = StyledButton.createButton('Stop Animation');
        stopBtn.onclick = ()=>{
            if (stopBtn.textContent.startsWith('Stop')) {
                this.stopAnimation();
                stopBtn.textContent = 'Start Animation';
            }
            else {
                this.refreshGraph(true);
                stopBtn.textContent = 'Stop Animation';
            }
        };
        var refreshBtn = StyledButton.createButton('Refresh Graph');
        refreshBtn.onclick = ()=>{
            this.refreshGraph()
        };
        return [deleteBtn, stopBtn, refreshBtn];
    }

    private restartSimulation(): void {
        this.simulation.alphaTarget(0.3)
            .velocityDecay(this.isAnimationStopped ? 1 : 0.5)
            .restart();
    }

    private defineSimulation(
        dataNodes: object[], dataLinks: object[], link: object, node: object, text: object, linkPath?: object, linkLabel?: object
    ) {
        this.simulation.nodes(dataNodes)
            .on("tick", () => {
                this.ticked(link, node, text, linkPath, linkLabel);
            });
        this.simulation.force("link")
            .links(dataLinks);
    }

    private formatNode(node: object): object {
        var dims = this.getSvgDimensions();
        return node.enter().append("circle")
                .attr("r", (d)=> {
                    console.log('node: '+JSON.stringify(d));
                    return this.radius;
                })
                // .attr("fill", (d) => { if (d.root == "true") return color(d.root); return color(d.type); })
                .attr("fill", "#4477ff")
                .attr("stroke", 'black')
                .attr("stroke-width", '1')
                .attr("cx", dims.x/2)
                .attr("cy", dims.y/2)
                .call(d3.drag()
                        .on("start", (d) => {
                            if (!d3.event.active) {
                                this.restartSimulation();
                            }
                            this.dragstarted(d);
                        })
                        .on("drag", this.dragged)
                        .on("end", (d) => {
                            if (!d3.event.active) {
                                this.simulation.alphaTarget(0);
                            }
                            this.dragended(d);
                        }));
    }
    private formatLink(link: object): object {
        return link.enter().append("line")
                .attr("stroke", (d) => {
                    console.log('link'+JSON.stringify(d))
                    return this.colorScheme(d.type);
                })
                .attr("stroke-width", "2")
                .attr("marker-end", "url(#arrow)");
    }
    private formatText(text: object): object {
        return text.enter().append("text")
                .attr('class', 'nodeLabel')
                .attr("x", this.radius+this.circleStrokeWidth)
                // .attr("y", '0.31em')
                .style("font-family", "sans-serif")
                .style("font-size", "11px")
                .style("pointer-events", "none")
                .text((d) => {
                    return d.method || (new URL(d.id)).pathname
                });
    }
    private formatLinkPath(linkPath: object): object {
        return linkPath.enter().append('path')
            .attr('class', 'linkPath')
            .attr('fill-opacity', 0)
            .attr('stroke-opacity', 0)
            .attr('fill', 'blue')
            .attr('stroke', 'red')
            .attr("id", this.getPathsToId)
            .style("pointer-events", "none")
    }
    private formatLinkLabel(linkLabel: object): object {
        return linkLabel.enter().append('text')
            .attr("dx", this.radius+this.circleStrokeWidth)
            .attr("dy", -2)
            .attr("id", (d) => {
                return 'labelPath_'+this.getPathsToId(d);
            })
            .attr('transform', (d) => {
                if (d.target.x<d.source.x) {
                    let dims = this.getBboxDimensions('labelPath_'+this.getPathsToId(d));
                    if (!dims) return 'rotate(0)';
                    var rx = dims.x+dims.width/2;
                    var ry = dims.y+dims.height/2;
                    return 'rotate(180 '+rx+' '+ry+')';
                }
                else {
                    return 'rotate(0)';
                }
            })
            .attr('class', 'linkLabel')
            .style("font-family", this.font)
            .style("font-size", this.fontSize)
            .style("pointer-events", "none")
            .append('textPath')
            .attr('id', (d)=>{return 'textPath_'+this.getPathsToId(d)})
            .attr('xlink:href', (d) => {
                return '#'+this.getPathsToId(d);
            })
            .text((d) => {
                return (new URL(d.target.id||d.target)).pathname
            });
    }

    private ticked(link: object, node: object, text: object, linkPath?: object, linkLabel?:object): void {
        let dims = this.getSvgDimensions();
        link && link
            .attr("x1", (d) => { return this.placeWithBoundary(d.source.x, dims.x); })
            .attr("y1", (d) => { return this.placeWithBoundary(d.source.y, dims.y); })
            .attr("x2", (d) => { return this.placeWithBoundary(d.target.x, dims.x); })
            .attr("y2", (d) => { return this.placeWithBoundary(d.target.y, dims.y); });
        node && node
            .attr("cx", (d) => { return this.placeWithBoundary(d.x, dims.x); })
            .attr("cy", (d) => { return this.placeWithBoundary(d.y, dims.y); });
        text && text
            .attr("transform", (d) => { return `translate(${this.placeWithBoundary(d.x, dims.x)},${this.placeWithBoundary(d.y, dims.y)})`; })
            .text((d) => {
                return d.method || (new URL(d.id)).pathname
            });
        linkPath && linkPath.attr('d', (d) => {
            let sx = d.source.x || d.x;
            let sy = d.source.y || d.y;
            let tx = d.target.x || d.x;
            let ty = d.target.y || d.y;
            return 'M '+sx+' '+sy+' L '+tx+' '+ty
        });
        linkLabel && linkLabel.attr('transform', (d) => {
            if (d.target.x<d.source.x) {
                let dims = this.getBboxDimensions('labelPath_'+this.getPathsToId(d));
                if (!dims) return 'rotate(0)';
                var rx = dims.x+dims.width/2;
                var ry = dims.y+dims.height/2;
                return `rotate(180 ${rx} ${ry})`;
            }
            else {
                return 'rotate(0)';
            }
        });
    }
    private placeWithBoundary(val: number, boundary: number) {
        // return val<0 ? 0 : Math.min(val, boundary);
        return val;
    }
    private dragstarted(d): void {
        d.fx = d.x;
        d.fy = d.y;
    }
    private dragged(d): void {
        d.fx = d3.event.x;
        d.fy = d3.event.y;
    }
    private dragended(d): void {
        d.fx = null;
        d.fy = null;
    }

    private getPathsToId(d) {
        let src = d.source.id || d.source;
        let target = d.target.id || d.target;
        return 'linkId_'+btoa(src+target);
    };
    private getSvgDimensions(): {[key: string]:number} {
        let dims = document.getElementById(this.svgId).getBoundingClientRect();
        return {'x':dims.width, 'y':dims.height,'xoff':dims.x,'yoff':dims.y};
    }
    private getBboxDimensions(id: string): object {
        if (!document.getElementById(id)) return null;
        return document.getElementById(id).getBBox();
    }
}
