
import * as d3 from "d3";
import { io } from "socket.io-client";

var svg = d3.select("body").select("svg");

var bbox = document.getElementById("graph").getBoundingClientRect()
var width = bbox.width;
var height = bbox.height;
console.log(width)
console.log(height)
// var width = svg.attr("width");
// var height = svg.attr("height");

svg = svg.call(d3.zoom().on("zoom", zoomed)).append("g");

svg.append("defs").append("marker")
    .attr("id", "arrow")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 20)
    .attr("refY", 0)
    .attr("markerWidth", 8)
    .attr("markerHeight", 8)
    .attr("orient", "auto")
    .append("svg:path")
    .attr("d", "M0,-5L10,0L0,5");

var color = d3.scaleOrdinal(d3.schemeCategory10);
const radius = 10;

var simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id((d) => { return d.id; }))
    .force("charge", d3.forceManyBody().strength(-1000))
    // .force("charge", d3.forceManyBody())
    // .force("center", d3.forceCenter(width / 2, height / 2))
    .force("x", d3.forceX(width / 2))
    .force("y", d3.forceY(height / 2))
    .force("collision", d3.forceCollide().radius(radius))

//d3.json("data.json", createGraph );

function createGraph(error, graph) {
    if (error) throw error;

    var link = svg.append("g")
        .attr("class", "links")
        .selectAll("line")
        .data(graph.links)
        .enter().append("line")
        .attr("stroke", (d) => { return color(d.type); })
        .attr("marker-end", "url(#arrow)");


    var node = svg.append("g")
        .attr("class", "nodes")
        .selectAll("circle")
        .data(graph.nodes)
        .enter().append("circle")
        .attr("r", radius)
        .attr("fill", (d) => { if (d.root == "true") return color(d.root); return color(d.type); })
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged));
    // .on("end", dragended));

    var text = svg.append("g")
        .attr("class", "labels")
        .selectAll("g")
        .data(graph.nodes)
        .enter().append("g");

    text.append("text")
        .attr("x", 20)
        // .attr("y", ".31em")
        .style("font-family", "sans-serif")
        .style("font-size", "0.7em")
        .text((d) => { return d.id; });

    node.on("click", (d) => {
        console.log("clicked", d.id);
    });

    // node.append("title")
    //     .text((d) => { return d.id; });

    simulation
        .nodes(graph.nodes)
        .on("tick", () => {
            link
                .attr("x1", (d) => { return d.source.x; })
                .attr("y1", (d) => { return d.source.y; })
                .attr("x2", (d) => { return d.target.x; })
                .attr("y2", (d) => { return d.target.y; });
            node
                .attr("cx", (d) => { return d.x; })
                .attr("cy", (d) => { return d.y; });
            text
                .attr("transform", (d) => { return `translate(${d.x},${d.y})`; })
        });

    simulation.force("link")
        .links(graph.links);
}


function dragstarted(d) {
    if (!d3.event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(d) {
    d.fx = d3.event.x;
    d.fy = d3.event.y;
}

function dragended(d) {
    if (!d3.event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

function zoomed() {
    svg.attr("transform", "translate(" + d3.event.transform.x + "," + d3.event.transform.y + ")" + " scale(" + d3.event.transform.k + ")");
}

var data = {
    "nodes": [

    ],
    "links": [

    ]
};

var isGraphCreated = false;

var knownPaths = new Set();
var knownPathsIndex = [];
var knownLinks = new Set();

const socket = io();
socket.on('data', (msg) => {
    console.log(msg);
    let dst = msg.host+msg.path;
    if (!(knownPaths.has(dst))) {
        knownPaths.add(dst);
        data.nodes.push({
            "id": dst,
            "type": 1
        });
    }
    if (msg.referer) {
        let src = msg.referer.host+msg.referer.path;
        if (!(knownPaths.has(src))) {
            knownPaths.add(src);
            data.nodes.push({
                "id": src,
                "type": 1
            });
        }
        let srcDstStr = src+dst;
        if (src!=dst && !(knownLinks.has(srcDstStr))) {
            knownLinks.add(srcDstStr);
            let type = knownPathsIndex.indexOf(src);
            if (type==-1) {
                knownPathsIndex.push(src);
                type = knownPathsIndex.indexOf(src);
            }
            console.log(type)
            data.links.push({
                "source": src,
                "target": dst,
                "type": 1
            });
        }
        console.log(data);
        if (isGraphCreated) {
            update();
        }
        else {
            isGraphCreated = true;
            createGraph(false, data);
        }
    }
});

var update = function() {

    // Update the nodes
    let node = svg.select('.nodes')
        .selectAll("circle").data(data.nodes);
    // Exit any old nodes
    node.exit().remove();
    // Enter any new nodes
    node = node.enter().append("circle")
                    .attr("r", radius)
                    .attr("fill", (d) => { if (d.root == "true") return color(d.root); return color(d.type); })
                    .attr("cx", width/2)
                    .attr("cy", height/2)
                    .call(d3.drag()
                        .on("start", dragstarted)
                        .on("drag", dragged))
                    .merge(node)
                    // .append("title")
                    // .text((d) => { return d.id; });

    // Update links
    let link = svg.select('.links')
        .selectAll("line")
        .data(data.links);
    // Exit any old links
    link.exit().remove();
    // Enter links
    link = link
        .enter().append("line")
        .attr("stroke", (d) => { return color(d.type); })
        .attr("marker-end", "url(#arrow)")
        .merge(link);

    let text = svg.select('.labels')
                .selectAll('g')
                .data(data.nodes);
    text.exit().remove();
    text = text.enter().append("g")
                    .append("text")
                    .attr("x", 20)
                    // .attr("y", 20)
                    .style("font-family", "sans-serif")
                    .style("font-size", "0.7em")
                    .text((d) => { return d.id; })
                    .merge(text);
    text = svg.select('.labels')
               .selectAll('g')

    // Redefine and restart simulation
    simulation.nodes(data.nodes)
              .on("tick", ticked);
    simulation.force("link")
              .links(data.links);
    simulation.restart();


    function ticked() {
        // var bbox = document.getElementById("graph").getBoundingClientRect()
        // var width = bbox.width;
        // var height = bbox.height;
        // var radius = 4;
        link
            .attr("x1", (d) => { return d.source.x; })
            .attr("y1", (d) => { return d.source.y; })
            .attr("x2", (d) => { return d.target.x; })
            .attr("y2", (d) => { return d.target.y; });
        node
            .attr("cx", (d) => { return d.x; })
            .attr("cy", (d) => { return d.y; });
        text
            .attr("transform", (d) => { return `translate(${d.x},${d.y})`; })
    }


}
