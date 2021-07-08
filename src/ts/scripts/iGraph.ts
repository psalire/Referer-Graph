
export default interface IGraph {
    createGraph(): IGraph;
    updateGraph(): IGraph;
    addSrcNode(): IGraph;
    addDstNode(): IGraph;
    addNode(): IGraph;
    addLink(): IGraph;
    updateNodeMethod(): IGraph;
}
