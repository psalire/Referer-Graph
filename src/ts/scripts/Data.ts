
export default class Data {
    private nodes: object[];
    private links: object[];
    private knownPathsSet: Set<string> = new Set();
    private knownLinksSet: Set<string> = new Set();
    private knownPathsIndex: Map<string,number> = new Map();
    private filters?: string[];

    constructor() {
        this.nodes = [];
        this.links = [];
    }

    public addDstNode(reqData: {[key: string]: any}): Data {
        let dst = reqData.protocol+'://'+reqData.host+reqData.path;
        if (!this.knownPathsSet.has(dst)) {
            this.knownPathsSet.add(dst);
            this.addNode(
                dst,
                reqData.referer ? reqData.method : null,
                reqData.statusCode,
                reqData.headers,
                null,
                1
            );
        }
        else {
            this.updateNodeMethod(dst, reqData.method);
            this.updateNodeReqHeaders(dst, reqData.headers);
        }
        return this;
    }
    public addSrcNode(refData: {[key: string]: any}, resHeaders: string): Data {
        let src = refData.protocol+'://'+refData.host+refData.path;
        if (!this.knownPathsSet.has(src)) {
            this.knownPathsSet.add(src);
            this.addNode(src, null, null, null, resHeaders, 1);
        }
        else {
            this.updateNodeResHeaders(src, resHeaders);
        }
        return this;
    }
    public addLink(reqData: {[key: string]: any}): Data {
        let dst = reqData.protocol+'://'+reqData.host+reqData.path;
        let src = reqData.referer.protocol+'://'+reqData.referer.host+reqData.referer.path;
        if (src==dst) return this;
        let srcDstStr = src+dst;
        if (!this.knownLinksSet.has(srcDstStr)) {
            this.knownLinksSet.add(srcDstStr);
            let srcDstHosts = reqData.referer.host+','+reqData.host;
            if (!this.knownPathsIndex.has(srcDstHosts)) {
                this.knownPathsIndex.set(srcDstHosts, Math.random());
            }
            let type = this.knownPathsIndex.get(srcDstHosts);
            this.links.push({
                'source': src,
                'target': dst,
                'method': reqData.method,
                'type': type
            });
        }
        else {
            this.updateLinkMethod(src, dst, reqData.method);
        }
        return this;
    }
    public setFilters(filters: string[]): void {
        this.filters = filters;
    }
    public clearFilters(): void {
        this.filters = undefined;
    }

    private addNode(id: string, method: string|null, statusCode: number|null, reqHeaders: string|null, resHeaders: string|null, type: number): void {
        this.nodes.push({
            'id': id,
            'method': method,
            'statusCode': statusCode,
            'reqHeaders': reqHeaders!=null ? [reqHeaders] : [],
            'resHeaders': resHeaders!=null ? [resHeaders] : [],
            'type': type
        });
    }
    private updateNodeMethod(id: string, method: string) {
        var i = this.nodes.findIndex(v => {
            return v.id==id&&v.method&&!v.method.includes(method)
        });
        i!=-1 && (this.nodes[i].method += '|'+method);
    }
    private updateLinkMethod(src: string, dst: string, method: string) {
        var i = this.links.findIndex(v => {
            return v.source==src&&v.target==dst&&v.method&&!v.method.includes(method)
        });
        i!=-1 && (this.links[i].method += '|'+method);
    }
    private updateNodeReqHeaders(id: string, header: string) {
        var i = this.nodes.findIndex(v => {
            return v.id==id&&v.reqHeaders&&!v.reqHeaders.includes(header)
        });
        i!=-1 && (this.nodes[i].reqHeaders = this.nodes[i].reqHeaders.concat(header));
    }
    private updateNodeResHeaders(id: string, header: string) {
        var i = this.nodes.findIndex(v => {
            return v.id==id&&v.resHeaders&&!v.resHeaders.includes(header)
        });
        i!=-1 && (this.nodes[i].resHeaders = this.nodes[i].resHeaders.concat(header));
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
                        // d3.js changes the object, so have to check val.{source,target}.id
                        var sourceVal = val.source.id || val.source;
                        var targetVal = val.target.id || val.target;
                        return !sourceVal.includes(f) && !targetVal.includes(f)
                    }
                )
            )
        }
        return this.links;
    }
    public getNode(index: number): object {
        if (this.filters !== undefined) {
            return this.nodes.filter(
                val => this.filters.every(
                    f => !val.id.includes(f)
                )
            )[index];
        }
        return this.nodes[index];
    }
    public clear(): Data {
        this.nodes.splice(0,this.nodes.length);
        this.links.splice(0,this.links.length);
        this.knownLinksSet.clear();
        this.knownPathsSet.clear();
        this.knownPathsIndex.clear();
        return this;
    }
}
