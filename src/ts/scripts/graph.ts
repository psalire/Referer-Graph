
import GraphBridge from "./GraphBridge";
import Data from "./Data"
import { io } from "socket.io-client";

window.onload = () => {
    var graph = new GraphBridge();

    const socket = io();
    socket.on('data', (msg) => {
        graph.data.addDstNode(msg);
        if (msg.referer) {
            graph.data.addSrcNode(msg);
            graph.data.addLink(msg);
            graph.getActiveGraph().updateGraph();
        }
    });

    window.dispatchEvent(new CustomEvent('graphLoaded'));
}
