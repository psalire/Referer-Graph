
export default class Data {
    private nodes: object[];
    private links: object[];

    constructor() {
        this.nodes = [];
        this.links = [];
    }

    public addNode(id: string, type: number): Data {
        this.nodes.push({
            'id': id,
            'type': type
        });
        return this;
    }
    public addLink(src: string, dst: string, method: string, type: number): Data {
        this.links.push({
            'source': src,
            'target': dst,
            'method': method,
            'type': type
        });
        return this;
    }

    public getNodes(): object[] {
        return this.nodes;
    }
    public getLinks(): object[] {
        return this.links;
    }
}
