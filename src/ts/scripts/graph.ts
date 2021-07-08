
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
        d3Graph.data.addLink(msg);
        if (!isGraphCreated) {
            isGraphCreated = true;
            d3Graph.createGraph();
        }
        d3Graph.updateGraph();
    }
});
