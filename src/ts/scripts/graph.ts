
import D3Graph from "./D3Graph";
import { io } from "socket.io-client";

var d3Graph = new D3Graph();

const socket = ;
d3Graph.createGraph();
socket.on('data', (msg) => {
    d3Graph.data.addDstNode(msg);
    if (msg.referer) {
        d3Graph.data.addSrcNode(msg);
        d3Graph.data.addLink(msg);
        d3Graph.updateGraph();
    }
});
