
import D3Graph from "./D3Graph";
import * as d3 from "d3";
import { io } from "socket.io-client";

var d3Graph = new D3Graph();

var isGraphCreated = false;
var knownPaths = new Set();
var knownPathsIndex = [];
var knownLinks = new Set();

const socket = io();
socket.on('data', (msg) => {
    console.log(msg);
    let dst = msg.protocol+'://'+msg.host+msg.path;
    if (!(knownPaths.has(dst))) {
        knownPaths.add(dst);
        d3Graph.data.addNode(dst, 1);
    }
    if (msg.referer) {
        let src = msg.referer.protocol+'://'+msg.referer.host+msg.referer.path;
        if (!(knownPaths.has(src))) {
            knownPaths.add(src);
            d3Graph.data.addNode(src, 1);
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
            d3Graph.data.addLink(src, dst, type);
        }
        // console.log(d3Graph.data.getNodes());
        // console.log(d3Graph.data.getLinks());
        if (isGraphCreated) {
            d3Graph.updateGraph();
        }
        else {
            isGraphCreated = true;
            d3Graph.createGraph();
        }
    }
});
