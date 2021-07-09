
import D3Graph from "./D3Graph";
import Data from "./Data"
import { io } from "socket.io-client";

var data = new Data();
var d3Graph = new D3Graph(data);

const socket = io();
d3Graph.createGraph();
socket.on('data', (msg) => {
    d3Graph.data.addDstNode(msg);
    if (msg.referer) {
        d3Graph.data.addSrcNode(msg);
        d3Graph.data.addLink(msg);
        d3Graph.updateGraph();
    }
});
