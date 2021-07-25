
export default class Data {
    private nodes: object[];
    private links: object[];
    private knownPaths: Set<string> = new Set();
    private knownLinks: Set<string> = new Set();
    private knownPathsIndex: Map<string,number> = new Map();
    private filters?: string[];

    constructor() {
        this.nodes = [];
        this.links = [];
    }

    public addDstNode(msg: {[key: string]: any}): Data {
        let dst = msg.protocol+'://'+msg.host+msg.path;
        if (!this.knownPaths.has(dst)) {
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
        if (!this.knownPaths.has(src)) {
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
        else {
            this.updateLinkMethod(src, dst, msg.method);
        }
        return this;
    }
    public setFilters(filters: string[]): void {
        this.filters = filters;
    }
    public clearFilters(): void {
        this.filters = undefined;
    }

    private addNode(id: string, method: string, type: number): void {
        this.nodes.push({
            'id': id,
            'method': method,
            'type': type
        });
    }
    private updateNodeMethod(id: string, method: string) {
        var i = this.nodes.findIndex(v => {
            console.log('V: '+JSON.stringify(v));
            return v.id==id&&v.method&&!v.method.includes(method)
        });
        i!=-1 && (this.nodes[i].method += '|'+method);
    }
    private updateLinkMethod(src: string, dst: string, method: string) {
        console.log('UPDATING LINK: '+src+','+dst+','+method);
        var i = this.links.findIndex(v => {
            return v.source==src&&v.target==dst&&v.method&&!v.method.includes(method)
        });
        console.log('i: '+i);
        console.log('links: '+JSON.stringify(this.links));
        console.log('link: '+JSON.stringify(this.links[i]));
        i!=-1 && (this.links[i].method += '|'+method);
    }
    public getNodes(): object[] {
        console.log('getNodes(): '+JSON.stringify(this.nodes))
        if (this.filters !== undefined) {
            return this.nodes.filter(
                val => this.filters.every(
                    f => !val.id.includes(f)
                )
            )
        }
        return this.nodes;
    }
    public getLinks(): object[] {
        console.log('getLinks(): '+JSON.stringify(this.links));
        if (this.filters !== undefined) {
            return this.links.filter(
                val => this.filters.every(
                    f => {
                        var sourceVal = val.source.id || val.source;
                        var targetVal = val.target.id || val.target;
                        return !sourceVal.includes(f) && !targetVal.includes(f)
                    }
                )
            )
        }
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
