export type TopologyPosition={x:number;y:number;z:number};
export type TopologyVisualNode={id:string;label:string;kind:string;position:TopologyPosition;confidence:string;sourceLine?:number};
export type TopologyVisualEdge={from:string;to:string;confidence:string;directed:true};
const hash=(s:string)=>{let h=2166136261;for(const c of s){h^=c.charCodeAt(0);h=Math.imul(h,16777619)}return h>>>0};
export function topologyScene(graph:{nodes:any[];edges:any[]}){
 const nodes:TopologyVisualNode[]=graph.nodes.map((n,i)=>{const seed=hash(String(n.id||n.label||i)),ring=i%16,layer=Math.floor(i/16),angle=(ring/16)*Math.PI*2+(seed%100)/500;
  const radius=180+(seed%70);return {id:String(n.id),label:String(n.label),kind:String(n.kind||'COMPONENT'),confidence:String(n.confidence||'INFERRED'),sourceLine:Number.isFinite(n.line)?n.line:undefined,position:{x:Math.round(Math.cos(angle)*radius),y:(layer-Math.floor(graph.nodes.length/32))*120,z:Math.round(Math.sin(angle)*radius)}}});
 const ids=new Set(nodes.map(n=>n.id)),edges:TopologyVisualEdge[]=graph.edges.filter(e=>ids.has(String(e.from))&&ids.has(String(e.to))&&e.from!==e.to).map(e=>({from:String(e.from),to:String(e.to),confidence:String(e.confidence||'EXPLICIT'),directed:true}));
 return {version:1,coordinateSystem:'AEGIS_TOPOLOGY_SCENE',geometrySemantics:'LAYOUT_ONLY_NOT_CAD',nodes,edges,warning:'Scene coordinates are deterministic visualization layout only. They are not physical dimensions, CAD coordinates, deployment proof, or inferred connectivity.'};
}
