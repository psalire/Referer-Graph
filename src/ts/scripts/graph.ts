
import GraphBridge from "./GraphBridge";
import Data from "./Data"
import { io } from "socket.io-client";

window.onload = () => {
    var graph = new GraphBridge();

    const socket = io();
    socket.on('data', (msg) => {
        graph.data.addDstNode(msg.requestData, msg.responseData.headers);
        if (msg.requestData.referer) {
            graph.data.addSrcNode(msg.requestData.referer).addLink(msg.requestData);
            graph.getIsLiveUpdateOn() && graph.getActiveGraph().updateGraph();
        }
    });

    window.dispatchEvent(new CustomEvent('graphLoaded'));
}
