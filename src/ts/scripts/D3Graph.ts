
import Data from './Data';
import * as d3 from "d3";

export default class D3Graph {
    private svg: any;
    private simulation: any;
    public data: Data;
    private readonly simulationStrength = -300;
    // private readonly colorScheme = d3.scaleOrdinal(d3.schemeCategory10);
    private readonly colorScheme = d3.scaleSequential(d3.interpolateRainbow);
    private readonly radius = 10;

    constructor(svgName='#graph') {
        this.svg = d3.select(svgName);
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
            .attr("refX", 16)
            .attr("refY", 0)
            .attr("markerWidth", 8)
            .attr("markerHeight", 8)
            .attr("orient", "auto")
            .append("svg:path")
            .attr("d", "M0,-5L10,0L0,5");
        let dims = this.getSvgDimensions();
        this.simulation = d3.forceSimulation()
            .force("link", d3.forceLink().id((d) => { return d.id; }))
            .force("charge", d3.forceManyBody().strength(this.simulationStrength))
            // .force("charge", d3.forceManyBody())
            // .force("center", d3.forceCenter(dims.x / 2, dims.y / 2))
            .force("x", d3.forceX(dims.x / 2))
            .force("y", d3.forceY(dims.y / 2))
            // .force("collision", d3.forceCollide().radius(radius))
        this.data = new Data();
    }

    public createGraph(): D3Graph {
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
            .selectAll("g")
            .data(dataNodes)
            .enter().append("g");

        this.formatText(text);

        node.on("click", (d) => {
            console.log("clicked", d.id);
        });

        // node.append("title")
        //     .text((d) => { return d.id; });

        this.simulation
            .nodes(dataNodes)
            .on("tick", () => {
                this.ticked(link, node, text);
            });
        this.simulation.force("link")
            .links(dataLinks);

        return this;
    }

    public updateGraph(): D3Graph {
        // var dims = this.getSvgDimensions();
        var dataLinks = this.data.getLinks();
        var dataNodes = this.data.getNodes();

        // Update the nodes
        var node = this.svg.select('.nodes')
                    .selectAll("circle").data(dataNodes);
        // Exit any old nodes
        node.exit().remove();
        // Enter any new nodes
        node = this.formatNode(node)
                .merge(node)
                // .append("title")
                // .text((d) => { return d.id; });

        // Update links
        var link = this.svg.select('.links')
                    .selectAll("line")
                    .data(dataLinks);
        // Exit any old links
        link.exit().remove();
        // Enter links
        link = this.formatLink(link)
                .merge(link);

        var text = this.svg.select('.labels')
                    .selectAll('g')
                    .data(dataNodes);
        text.exit().remove();
        text = text.enter().append("g");
        this.formatText(text).merge(text);
        text = this.svg.select('.labels')
                .selectAll('g')

        // Redefine and restart simulation
        this.simulation.nodes(dataNodes)
            .on("tick", () => {
                this.ticked(link, node, text);
            });
        this.simulation.force("link")
            .links(dataLinks);
        this.simulation.alphaTarget(0.3).restart();

        return this;
    }

    private formatNode(node: object): object {
        var dims = this.getSvgDimensions();
        return node.enter().append("circle")
                .attr("r", this.radius)
                // .attr("fill", (d) => { if (d.root == "true") return color(d.root); return color(d.type); })
                .attr("fill", "#4477ff")
                .attr("stroke", 'black')
                .attr("stroke-width", '1')
                .attr("cx", dims.x/2)
                .attr("cy", dims.y/2)
                .call(d3.drag()
                        .on("start", (d) => {
                            if (!d3.event.active) this.simulation.alphaTarget(0.3).restart();
                            this.dragstarted(d);
                        })
                        .on("drag", this.dragged)
                        .on("end", (d) => {
                            if (!d3.event.active) this.simulation.alphaTarget(0);
                            this.dragended(d);
                        }));
    }
    private formatLink(link: object): object {
        return link.enter().append("line")
                .attr("stroke", (d) => { return this.colorScheme(d.type); })
                .attr("stroke-width", "2")
                .attr("marker-end", "url(#arrow)");
    }
    private formatText(text: object): object {
        return text.append("text")
                .attr("x", 15)
                .attr("y", '0.31em')
                .style("font-family", "sans-serif")
                .style("font-size", "0.7em")
                .text((d) => { return (new URL(d.id)).pathname; });
    }

    private ticked(link, node, text): void {
        let dims = this.getSvgDimensions();
        link
            .attr("x1", (d) => { return this.placeWithBoundary(d.source.x, dims.x); })
            .attr("y1", (d) => { return this.placeWithBoundary(d.source.y, dims.y); })
            .attr("x2", (d) => { return this.placeWithBoundary(d.target.x, dims.x); })
            .attr("y2", (d) => { return this.placeWithBoundary(d.target.y, dims.y); });
        node
            .attr("cx", (d) => { return this.placeWithBoundary(d.x, dims.x); })
            .attr("cy", (d) => { return this.placeWithBoundary(d.y, dims.y); });
        text
            .attr("transform", (d) => { return `translate(${this.placeWithBoundary(d.x, dims.x)},${this.placeWithBoundary(d.y, dims.y)})`; })
    }
    private placeWithBoundary(val: number, boundary: number) {
        return val;
        // return val<0 ? 0 : Math.min(val, boundary);
    }
    private dragstarted(d): void {
        // if (!d3.event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
    }
    private dragged(d): void {
        d.fx = d3.event.x;
        d.fy = d3.event.y;
    }
    private dragended(d): void {
        // if (!d3.event.active) this.simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
    }

    private getSvgDimensions(): {[key: string]:number} {
        let dims = document.getElementById("graph").getBoundingClientRect();
        return {'x':dims.width, 'y':dims.height};
    }
}
