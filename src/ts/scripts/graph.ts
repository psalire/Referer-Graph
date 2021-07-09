
import D3Graph from "./D3Graph";
import Data from "./Data"
import { io } from "socket.io-client";

function createButton(text: string): HTMLButtonElement {
    var btn = document.createElement('button');
    btn.textContent = text;
    return btn;
}

window.onload = () => {
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

    var deleteBtn = createButton('Delete Graph');
    deleteBtn.onclick = ()=>{d3Graph.deleteGraph()};
    var refreshBtn = createButton('Refresh Graph');
    refreshBtn.onclick = ()=>{d3Graph.refreshGraph()};
    var stopBtn = createButton('Stop Animation');
    stopBtn.onclick = ()=>{d3Graph.stopAnimation()};
    var btnContainer = document.getElementById('buttons');
    btnContainer.appendChild(deleteBtn);
    btnContainer.appendChild(refreshBtn);
    btnContainer.appendChild(stopBtn);
    window.dispatchEvent(new CustomEvent('graphLoaded'));
}
