
export default class Data {
    private nodes: object[];
    private links: object[];
    private knownPaths: Set<string> = new Set();
    private knownLinks: Set<string> = new Set();
    private knownPathsIndex: Map<string,number> = new Map();

    constructor() {
        this.nodes = [];
        this.links = [];
    }

    public addDstNode(msg: {[key: string]: any}): Data {
        let dst = msg.protocol+'://'+msg.host+msg.path;
        if (!(this.knownPaths.has(dst))) {
            this.knownPaths.add(dst);
            this.addNode(dst, msg.referer ? msg.method : null, 1);
        }
        else {
            this.updateNodeMethod(dst, msg.method);
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
    public addLink(msg: {[key: string]: any}): Data {
        let dst = msg.protocol+'://'+msg.host+msg.path;
        let src = msg.referer.protocol+'://'+msg.referer.host+msg.referer.path;
        if (src==dst) return this;
        let srcDstStr = src+dst;
        if (!this.knownLinks.has(srcDstStr)) {
            this.knownLinks.add(srcDstStr);
            let srcDstHosts = msg.referer.host+','+msg.host;
            if (!this.knownPathsIndex.has(srcDstHosts)) {
                this.knownPathsIndex.set(srcDstHosts, Math.random());
            }
            let type = this.knownPathsIndex.get(srcDstHosts);
            this.links.push({
                'source': src,
                'target': dst,
                'method': msg.method,
                'type': type
            });
        }
        return this;
    }

    private addNode(id: string, method: string, type: number): void {
        this.nodes.push({
            'id': id,
            'method': method,
            'type': type
        });
    }
    private updateNodeMethod(id: string, method: string) {
        var i = this.nodes.findIndex(v => v.id==id&&v.method&&!v.method.includes(method));
        i!=-1 && (this.nodes[i].method += '|'+method);
    }
    public getNodes(): object[] {
        return this.nodes;
    }
    public getLinks(): object[] {
        return this.links;
    }
    public clear(): Data {
        this.nodes.splice(0,this.nodes.length);
        this.links.splice(0,this.links.length);
        this.knownLinks.clear();
        this.knownPaths.clear();
        this.knownPathsIndex.clear();
        return this;
    }
}
