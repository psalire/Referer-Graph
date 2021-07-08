
export default class Data {
    private nodes: object[];
    private links: object[];
    private knownPaths: Set<string> = new Set();

    constructor() {
        this.nodes = [];
        this.links = [];
    }

    // public addNode(id: string, method: string, type: number): Data {
    public addDstNode(msg: {[key: string]: any}): Data {
        let dst = msg.protocol+'://'+msg.host+msg.path;
        let dstWithMethod = msg.method+dst;
        if (!(this.knownPaths.has(dstWithMethod))) {
            this.knownPaths.add(dstWithMethod);
            this.addNode(dst, msg.method, 1);
        }
        return this;
    }
    public addSrcNode(msg: {[key: string]: any}): Data {
        let src = msg.referer.protocol+'://'+msg.referer.host+msg.referer.path;
        if (!(this.knownPaths.has(src))) {
            this.knownPaths.add(src);
            this.addNode(src, null, 1);
        }
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

    private addNode(id: string, method: string, type: number): void {
        this.nodes.push({
            'id': id,
            'method': method,
            'type': type
        });
    }
    public getNodes(): object[] {
        return this.nodes;
    }
    public getLinks(): object[] {
        return this.links;
    }
}
