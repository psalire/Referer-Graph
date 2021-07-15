
export default interface iGraph {
    createGraph(): iGraph;
    updateGraph(): iGraph;
    deleteGraph(): iGraph;
    refreshGraph(): iGraph;
    getButtons(): HTMLButtonElement[];
}
