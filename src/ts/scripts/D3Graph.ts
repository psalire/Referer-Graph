
import Data from './Data';
import * as d3 from "d3";

export default class D3Graph {
    private svg: any;
    private simulation: any;
    public data: Data;
    private readonly simulationStrength = -400;
    private readonly colorScheme = d3.scaleSequential(d3.interpolateRainbow);
    private readonly radius = 17;

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
            .attr("refX", 20)
            .attr("refY", 0)
            .attr("markerWidth", 8)
            .attr("markerHeight", 8)
            .attr("orient", "auto")
            .append("svg:path")
            .attr("d", "M0,-5L10,0L0,5");
        let dims = this.getSvgDimensions();
        this.simulation = d3.forceSimulation()
            .force("link", d3.forceLink().distance(150).id((d) => { return d.id; }))
            .force("charge", d3.forceManyBody().strength(this.simulationStrength))
            // .force("charge", d3.forceManyBody())
            // .force("center", d3.forceCenter(dims.x / 2, dims.y / 2))
            .force("x", d3.forceX(dims.x / 2))
            .force("y", d3.forceY(dims.y / 2))
            .force("collision", d3.forceCollide().radius(this.radius+2))
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

        this.defineSimulation(dataNodes, dataLinks, link, node, text);

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

        // Update link labels
        var linkPath = this.svg.select('.links')
                        .selectAll('.linkPath')
                        .data(dataLinks);
        linkPath.exit().remove();
        linkPath = linkPath.enter().append('path')
            .attr('d', (d) => {
                return 'M '+d.source.x+' '+d.source.y+' L '+ d.target.x +' '+d.target.y
            }).attr('class', 'linkPath')
            .attr('fill-opacity', 0)
            .attr('stroke-opacity', 0)
            .attr('fill', 'blue')
            .attr('stroke', 'red')
            .attr("id", this.getPathsToId)
            .style("pointer-events", "none")
            .merge(linkPath)

        var linkLabel = this.svg.select('.links')
                            .selectAll('.linkLabel')
                            .data(dataLinks);
        linkLabel.exit().remove();
        linkLabel = linkLabel.enter().append('text')
            .attr("dx", (d)=>{return 75-d.method.length*8})
            .attr("dy", -2)
            .attr("id", (d) => {
                return 'label_'+this.getPathsToId(d);
            })
            .attr('class', 'linkLabel')
            .style("font-family", "sans-serif")
            .style("font-size", "12px")
            .style("pointer-events", "none")
            .append('textPath')
            .attr('xlink:href', (d) => {
                return '#'+this.getPathsToId(d);
            })
            .text((d) => {return d.method})
            .merge(linkLabel);

        var text = this.svg.select('.labels')
                    .selectAll('g')
                    .data(dataNodes);
        text.exit().remove();
        text.enter().append("g");
        this.formatText(text).merge(text);
        text = this.svg.select('.labels')
                .selectAll('g')

        // Redefine and restart simulation
        this.defineSimulation(dataNodes, dataLinks, link, node, text, linkPath, linkLabel);
        this.simulation.alphaTarget(0.3).restart();

        return this;
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
                .attr("x", 22)
                .attr("y", '0.31em')
                .style("font-family", "sans-serif")
                .style("font-size", "0.7em")
                .text((d) => { return (new URL(d.id)).pathname; });
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
        linkPath && linkPath.attr('d', (d) => {
            var path='M '+d.source.x+' '+d.source.y+' L '+ d.target.x +' '+d.target.y;
            return path
        });
        linkLabel && linkLabel.attr('transform', (d) => {
            if (d.target.x<d.source.x) {
                let dims = this.getBboxDimensions('label_'+this.getPathsToId(d));
                var rx = dims.x+dims.width/2;
                var ry = dims.y+dims.height/2;
                return 'rotate(180 '+rx+' '+ry+')';
            }
            else {
                return 'rotate(0)';
            }
        })
        .attr('dy', (d) => (d.target.x<d.source.x) ? '10' : '-2');
    }
    private placeWithBoundary(val: number, boundary: number) {
        return val;
        // return val<0 ? 0 : Math.min(val, boundary);
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
    private getSvgDimensions(id='graph'): {[key: string]:number} {
        let dims = document.getElementById(id).getBoundingClientRect();
        return {'x':dims.width, 'y':dims.height,'xoff':dims.x,'yoff':dims.y};
    }
    private getBboxDimensions(id: string): object {
        return document.getElementById(id).getBBox();
    }
}
