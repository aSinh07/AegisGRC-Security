export type IntelItem={title:string;link:string;publishedAt:string;source:string;summary:string};
const sources=[
 {source:'CISA Advisories',url:'https://www.cisa.gov/cybersecurity-advisories/all.xml'},
 {source:'NIST News',url:'https://www.nist.gov/news-events/news/rss.xml'}
];
function clean(s:string){return s.replace(/<[^>]+>/g,' ').replace(/&amp;/g,'&').replace(/\s+/g,' ').trim()}
function value(block:string,name:string){const a=block.toLowerCase().indexOf('<'+name.toLowerCase());if(a<0)return '';const start=block.indexOf('>',a)+1,end=block.toLowerCase().indexOf('</'+name.toLowerCase()+'>',start);return end<0?'':clean(block.slice(start,end).replace('<![CDATA[','').replace(']]>',''))}
async function read(source:string,url:string){const r=await fetch(url,{headers:{'User-Agent':'AegisGRC-Security'}});if(!r.ok)throw Error(source+' feed unavailable');const xml=await r.text(),out:IntelItem[]=[];for(const block of xml.split('<item').slice(1,13)){const title=value(block,'title'),link=value(block,'link');if(title&&link)out.push({title,link,publishedAt:value(block,'pubDate'),source,summary:value(block,'description').slice(0,600)})}return out}
let cache:{at:number,items:IntelItem[],errors:string[]}|null=null;
export async function cyberIntel(force=false){if(!force&&cache&&Date.now()-cache.at<900000)return {...cache,cache:'HIT'};const results=await Promise.allSettled(sources.map(x=>read(x.source,x.url))),items:IntelItem[]=[],errors:string[]=[];results.forEach((x,i)=>x.status==='fulfilled'?items.push(...x.value):errors.push(sources[i].source));items.sort((a,b)=>Date.parse(b.publishedAt||'0')-Date.parse(a.publishedAt||'0'));cache={at:Date.now(),items:items.slice(0,24),errors};return {...cache,cache:'REFRESHED'}}
