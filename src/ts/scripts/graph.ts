
import D3Graph from "./D3Graph";
import * as d3 from "d3";
import { io } from "socket.io-client";

var d3Graph = new D3Graph();

var isGraphCreated = false;
var knownPathsIndex = {};
var knownLinks = new Set();

const socket = io();
socket.on('data', (msg) => {
    d3Graph.data.addDstNode(msg);
    if (msg.referer) {
        d3Graph.data.addSrcNode(msg);
        let dst = msg.protocol+'://'+msg.host+msg.path;
        let src = msg.referer.protocol+'://'+msg.referer.host+msg.referer.path;
        if (src==dst) return;
        let srcDstStr = src+dst+msg.method;
        if (!(knownLinks.has(srcDstStr))) {
            knownLinks.add(srcDstStr);
            let srcDstHosts = msg.referer.host+','+msg.host;
            if (!(srcDstHosts in knownPathsIndex)) {
                knownPathsIndex[srcDstHosts] = Math.random();
            }
            let type = knownPathsIndex[srcDstHosts];
            console.log(srcDstHosts);
            console.log(type)
            d3Graph.data.addLink(src, dst, msg.method, type);
        }
        if (!isGraphCreated) {
            isGraphCreated = true;
            d3Graph.createGraph();
        }
        d3Graph.updateGraph();
    }
});
