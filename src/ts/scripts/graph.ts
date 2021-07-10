
import D3Graph from "./D3Graph";
import DagreGraph from "./DagreGraph";
import Data from "./Data"
import { io } from "socket.io-client";

function createButton(text: string): HTMLButtonElement {
    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-primary mb-1';
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

    var deleteBtn = createButton('Clear Graph');
    deleteBtn.onclick = ()=>{
        d3Graph.data.clear();
        d3Graph.refreshGraph();
    };
    var stopBtn = createButton('Stop Animation');
    stopBtn.onclick = ()=>{
        if (stopBtn.textContent.startsWith('Stop')) {
            d3Graph.stopAnimation();
            stopBtn.textContent = 'Start Animation';
        }
        else {
            d3Graph.refreshGraph(true);
            stopBtn.textContent = 'Stop Animation';
        }
    };
    var refreshBtn = createButton('Refresh Graph');
    refreshBtn.onclick = ()=>{
        d3Graph.refreshGraph()
    };
    var btnContainer = document.getElementById('buttons');
    btnContainer.appendChild(deleteBtn);
    btnContainer.appendChild(stopBtn);
    btnContainer.appendChild(refreshBtn);
    window.dispatchEvent(new CustomEvent('graphLoaded'));
}
