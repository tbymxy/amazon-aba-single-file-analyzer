const HEADER_SIZE = 64;
const BLOCK_SIZE = 100;
const ANALYSIS_MAGIC = 0x32414241;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');
const normalize = (value) => String(value || '').trim().toLowerCase().replace(/\s+/g, ' ');
const asNumber = (value) => Number(String(value || '').replaceAll('%', '').replaceAll(',', '').trim()) || 0;
const hashPair = (value) => {
  let first = 2166136261, second = 5381;
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index);
    first = Math.imul(first ^ code, 16777619);
    second = Math.imul(second, 33) ^ code;
  }
  return [first >>> 0, second >>> 0];
};

async function reportDirectory() {
  if (!navigator.storage?.getDirectory) return null;
  const root = await navigator.storage.getDirectory();
  return root.getDirectoryHandle('aba-reports', { create: true });
}

class Sha256 {
  static K = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  constructor() {
    this.h = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
    this.buffer = new Uint8Array(64); this.bufferLength = 0; this.bytes = 0; this.words = new Uint32Array(64);
  }
  update(data) {
    this.bytes += data.length;
    let offset = 0;
    if (this.bufferLength) {
      const take = Math.min(64 - this.bufferLength, data.length);
      this.buffer.set(data.subarray(0, take), this.bufferLength); this.bufferLength += take; offset += take;
      if (this.bufferLength === 64) { this.compress(this.buffer); this.bufferLength = 0; }
    }
    while (offset + 64 <= data.length) { this.compress(data.subarray(offset, offset + 64)); offset += 64; }
    if (offset < data.length) { this.buffer.set(data.subarray(offset), 0); this.bufferLength = data.length - offset; }
  }
  compress(block) {
    const w = this.words;
    for (let i = 0; i < 16; i++) { const p = i * 4; w[i] = ((block[p] << 24) | (block[p+1] << 16) | (block[p+2] << 8) | block[p+3]) >>> 0; }
    for (let i = 16; i < 64; i++) {
      const a=w[i-15], b=w[i-2];
      const s0=((a>>>7)|(a<<25))^((a>>>18)|(a<<14))^(a>>>3);
      const s1=((b>>>17)|(b<<15))^((b>>>19)|(b<<13))^(b>>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    let [a,b,c,d,e,f,g,h]=this.h;
    for (let i=0;i<64;i++) {
      const s1=((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7));
      const ch=(e&f)^(~e&g); const t1=(h+s1+ch+Sha256.K[i]+w[i])>>>0;
      const s0=((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10));
      const maj=(a&b)^(a&c)^(b&c); const t2=(s0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    this.h[0]=(this.h[0]+a)>>>0;this.h[1]=(this.h[1]+b)>>>0;this.h[2]=(this.h[2]+c)>>>0;this.h[3]=(this.h[3]+d)>>>0;
    this.h[4]=(this.h[4]+e)>>>0;this.h[5]=(this.h[5]+f)>>>0;this.h[6]=(this.h[6]+g)>>>0;this.h[7]=(this.h[7]+h)>>>0;
  }
  hex() {
    const length = this.bufferLength < 56 ? 64 : 128;
    const final = new Uint8Array(length); final.set(this.buffer.subarray(0, this.bufferLength)); final[this.bufferLength]=0x80;
    const bits=this.bytes*8, view=new DataView(final.buffer);
    view.setUint32(length-8, Math.floor(bits/0x100000000), false); view.setUint32(length-4, bits>>>0, false);
    for(let offset=0;offset<length;offset+=64)this.compress(final.subarray(offset,offset+64));
    return Array.from(this.h, value=>value.toString(16).padStart(8,'0')).join('');
  }
}

class StreamingCsvParser {
  constructor(onRecord) { this.onRecord=onRecord; this.record=[]; this.cell=''; this.column=0; this.quoted=false; this.pendingQuote=false; this.skipLf=false; this.cellStarted=false; this.capture=null; }
  setCapture(indexes) { this.capture=new Set(indexes); }
  capturing() { return !this.capture || this.capture.has(this.column); }
  append(character) { if (this.capturing()) this.cell += character; this.cellStarted=true; }
  finishCell() { if (this.capturing()) this.record[this.column]=this.cell; this.cell=''; this.column++; this.cellStarted=false; }
  finishRecord() { this.finishCell(); this.onRecord(this.record); this.record=[]; this.column=0; }
  feed(text) {
    for (let i=0;i<text.length;i++) {
      const char=text[i];
      if(this.skipLf){this.skipLf=false;if(char==='\n')continue;}
      if(this.pendingQuote){this.pendingQuote=false;if(char==='"'){this.append('"');continue;}this.quoted=false;}
      if(this.quoted){if(char==='"'){this.pendingQuote=true;continue;}this.append(char);continue;}
      if(char==='"'&&!this.cellStarted){this.quoted=true;this.cellStarted=true;continue;}
      if(char===','){this.finishCell();continue;}
      if(char==='\n'){this.finishRecord();continue;}
      if(char==='\r'){this.finishRecord();this.skipLf=true;continue;}
      this.append(char);
    }
  }
  finish() { if(this.pendingQuote){this.pendingQuote=false;this.quoted=false;} if(this.cellStarted||this.column||this.record.length)this.finishRecord(); }
}

class Uint32Triples {
  constructor(size=131072){this.size=size;this.first=[];this.second=[];this.ranks=[];this.count=0;this.offset=0;}
  add(a,b,rank){if(!this.offset||this.offset===this.size){this.first.push(new Uint32Array(this.size));this.second.push(new Uint32Array(this.size));this.ranks.push(new Uint32Array(this.size));this.offset=0;}const i=this.first.length-1;this.first[i][this.offset]=a;this.second[i][this.offset]=b;this.ranks[i][this.offset]=rank;this.offset++;this.count++;}
  flatten(){const a=new Uint32Array(this.count),b=new Uint32Array(this.count),r=new Uint32Array(this.count);let at=0;for(let i=0;i<this.first.length;i++){const take=Math.min(this.size,this.count-at);a.set(this.first[i].subarray(0,take),at);b.set(this.second[i].subarray(0,take),at);r.set(this.ranks[i].subarray(0,take),at);at+=take;}return{first:a,second:b,ranks:r};}
}

class AnalysisWriter {
  constructor(directory,fileName,writable){this.directory=directory;this.fileName=fileName;this.writable=writable;this.buffer=new Uint8Array(8*1024*1024);this.position=0;this.logical=HEADER_SIZE;this.ready=[];this.offsets=[];this.count=0;}
  static async create(directory,fileName){const handle=await directory.getFileHandle(fileName,{create:true});const writable=await handle.createWritable();await writable.write(new Uint8Array(HEADER_SIZE));return new AnalysisWriter(directory,fileName,writable);}
  add(rank,term,click,conversion){const bytes=encoder.encode(term),length=24+bytes.length;if(this.count%BLOCK_SIZE===0)this.offsets.push(this.logical);if(length>this.buffer.length){if(this.position){this.ready.push(this.buffer.subarray(0,this.position));this.position=0;}const row=new Uint8Array(length);this.writeRow(row,0,rank,click,conversion,bytes);this.ready.push(row);}else{if(this.position+length>this.buffer.length){this.ready.push(this.buffer.subarray(0,this.position));this.buffer=new Uint8Array(8*1024*1024);this.position=0;}this.writeRow(this.buffer,this.position,rank,click,conversion,bytes);this.position+=length;}this.logical+=length;this.count++;}
  writeRow(target,offset,rank,click,conversion,bytes){const view=new DataView(target.buffer,target.byteOffset+offset,24);view.setUint32(0,rank,true);view.setFloat64(4,click,true);view.setFloat64(12,conversion,true);view.setUint32(20,bytes.length,true);target.set(bytes,offset+24);}
  async flush(){for(const block of this.ready)await this.writable.write(block);this.ready=[];}
  async finish(){if(this.position){this.ready.push(this.buffer.subarray(0,this.position));this.position=0;}await this.flush();const indexOffset=this.logical;this.offsets.push(indexOffset);const index=new ArrayBuffer(this.offsets.length*8),view=new DataView(index);this.offsets.forEach((offset,i)=>view.setBigUint64(i*8,BigInt(offset),true));await this.writable.write(index);const header=new ArrayBuffer(HEADER_SIZE),h=new DataView(header);h.setUint32(0,ANALYSIS_MAGIC,true);h.setUint32(4,2,true);h.setUint32(8,this.count,true);h.setUint32(12,BLOCK_SIZE,true);h.setBigUint64(16,BigInt(indexOffset),true);h.setBigUint64(24,BigInt(indexOffset),true);h.setUint32(32,this.offsets.length-1,true);await this.writable.seek(0);await this.writable.write(header);await this.writable.close();return this.fileName;}
  async abort(){try{await this.writable.abort();}catch{}try{await this.directory.removeEntry(this.fileName);}catch{}}
}

function reportPeriod(firstRecord){const source=firstRecord.join(' ').replace(/^\uFEFF/,'');const match=/周\s*(\d+)\s*\|\s*(\d{4}-\d{2}-\d{2})\s*-\s*(\d{4}-\d{2}-\d{2})/.exec(source)||/Week\s*(\d+)\s*\|\s*(\d{4}-\d{2}-\d{2})\s*-\s*(\d{4}-\d{2}-\d{2})/i.exec(source);if(!match)return null;return{weekNumber:Number(match[1]),startDate:match[2],endDate:match[3],label:`周 ${Number(match[1])} | ${match[2]} - ${match[3]}`};}
function fieldIndexes(headers){const fields=headers.map((raw,index)=>({index,value:normalize(raw)}));const rank=fields.find(f=>f.value==='搜索频率排名'||f.value==='search frequency rank');const term=fields.find(f=>f.value==='搜索词'||f.value==='search term');const click=fields.filter(f=>f.value.includes('点击份额')||f.value.includes('click share')).slice(0,3);const conversion=fields.filter(f=>f.value.includes('转化贡献')||f.value.includes('conversion share')).slice(0,3);if(!rank||!term||click.length<3||conversion.length<3)throw new Error('无法识别 ABA 核心字段，请确认选择的是热门搜索词简单报告 CSV。');return{rank:rank.index,term:term.index,click:click.map(f=>f.index),conversion:conversion.map(f=>f.index)};}

function radixSort(first,second,ranks,token){let order=new Uint32Array(first.length),temporary=new Uint32Array(first.length);for(let i=0;i<order.length;i++)order[i]=i;const count=new Uint32Array(65536);const keys=[ranks,ranks,second,second,first,first];for(let pass=0;pass<6;pass++){count.fill(0);const shift=(pass%2)*16,key=keys[pass];for(let i=0;i<order.length;i++)count[(key[order[i]]>>>shift)&65535]++;let sum=0;for(let i=0;i<count.length;i++){const value=count[i];count[i]=sum;sum+=value;}for(let i=0;i<order.length;i++){const item=order[i];temporary[count[(key[item]>>>shift)&65535]++]=item;}const swap=order;order=temporary;temporary=swap;self.postMessage({type:'index-stage',token,stage:pass+1,totalStages:7,count:first.length});}return order;}
async function saveTrendArrays(directory,fileName,triples,token){const {first,second,ranks}=triples.flatten(),order=radixSort(first,second,ranks,token);const buffer=new ArrayBuffer(12+order.length*12),view=new DataView(buffer);view.setUint32(0,0x41424154,true);view.setUint32(4,1,true);view.setUint32(8,order.length,true);for(let position=0;position<order.length;position++){const source=order[position],offset=12+position*12;view.setUint32(offset,first[source],true);view.setUint32(offset+4,second[source],true);view.setUint32(offset+8,ranks[source],true);}self.postMessage({type:'index-stage',token,stage:7,totalStages:7,count:order.length});const writable=await(await directory.getFileHandle(fileName,{create:true})).createWritable();await writable.write(buffer);await writable.close();return fileName;}

async function importReport(file,site,token,index,total){const directory=await reportDirectory();if(!directory)throw new Error('当前浏览器不支持本地持久化存储。');const safe=String(token).replace(/[^a-zA-Z0-9-]/g,'')+'-'+index;const storageFile=`${site}_import_${safe}.aba2`,trendFile=`${site}_import_${safe}.trend.bin`;const writer=await AnalysisWriter.create(directory,storageFile);const triples=new Uint32Triples();const sha=new Sha256();let period=null,indexes=null,sourceRow=0,lastRank=0,readBytes=0,lastProgress=0;let csv;
  try{
    csv=new StreamingCsvParser((record)=>{if(sourceRow++===0){period=reportPeriod(record);return;}if(!indexes){try{indexes=fieldIndexes(record);csv.setCapture([indexes.rank,indexes.term,...indexes.click,...indexes.conversion]);}catch{}return;}const rank=Number(record[indexes.rank]),term=String(record[indexes.term]||'').trim();if(!Number.isFinite(rank)||rank<1||!term)return;if(rank<lastRank)throw new Error(`第 ${sourceRow.toLocaleString()} 条数据的排名顺序异常，请重新下载报告。`);lastRank=rank;const click=indexes.click.reduce((sum,field)=>sum+asNumber(record[field]),0),conversion=indexes.conversion.reduce((sum,field)=>sum+asNumber(record[field]),0);writer.add(rank,term,click,conversion);const pair=hashPair(normalize(term));triples.add(pair[0],pair[1],rank);});
    const reader=file.stream().getReader(),textDecoder=new TextDecoder('utf-8');
    while(true){const {value,done}=await reader.read();if(done)break;sha.update(value);readBytes+=value.length;csv.feed(textDecoder.decode(value,{stream:true}));await writer.flush();const percent=Math.min(99,Math.floor(readBytes/Math.max(1,file.size)*100));if(percent!==lastProgress){lastProgress=percent;self.postMessage({type:'progress',token,index,total,percent,count:writer.count,bytes:readBytes});}}
    csv.feed(textDecoder.decode());csv.finish();await writer.flush();if(!period)throw new Error('无法从 CSV 第一行识别周数与日期。');if(!indexes)throw new Error('未找到 ABA 表头。');if(!writer.count)throw new Error('报告中没有可用的搜索词数据。');const hash=sha.hex();await writer.finish();await saveTrendArrays(directory,trendFile,triples,token);return{period,fileHash:hash,storageFile,trendFile,rowCount:writer.count,storageVersion:2};
  }catch(error){await writer.abort();try{await directory.removeEntry(trendFile);}catch{}throw error;}
}

async function loadLegacyReport(fileName,token,index,total,progressType='load-progress'){if(typeof DecompressionStream==='undefined')throw new Error('当前浏览器不支持读取本地压缩报告。');const directory=await reportDirectory(),handle=await directory.getFileHandle(fileName),file=await handle.getFile(),reader=file.stream().pipeThrough(new DecompressionStream('gzip')).getReader(),textDecoder=new TextDecoder('utf-8');const records=[];let pending='';while(true){const{value,done}=await reader.read();if(done)break;pending+=textDecoder.decode(value,{stream:true});const lines=pending.split('\n');pending=lines.pop()||'';for(const line of lines){if(!line)continue;const item=JSON.parse(line),term=String(item[1]);records.push({rank:Number(item[0]),term,searchKey:normalize(term),top3Click:Number(item[2]),top3Conversion:Number(item[3])});}if(records.length&&records.length%50000<5000)self.postMessage({type:progressType,token,index,total,count:records.length});}if(pending.trim()){const item=JSON.parse(pending),term=String(item[1]);records.push({rank:Number(item[0]),term,searchKey:normalize(term),top3Click:Number(item[2]),top3Conversion:Number(item[3])});}return records;}
async function saveLegacyTrend(report,records,token,forcedFileName){const directory=await reportDirectory(),triples=new Uint32Triples();for(const row of records){const pair=hashPair(row.searchKey);triples.add(pair[0],pair[1],row.rank);}return saveTrendArrays(directory,forcedFileName||String(report.storageFile).replace(/\.jsonl\.gz$/,'.trend.bin'),triples,token);}

const trendBuffers=new Map();
async function readTrendIndex(fileName){if(trendBuffers.has(fileName))return trendBuffers.get(fileName);const directory=await reportDirectory(),file=await(await directory.getFileHandle(fileName)).getFile(),buffer=await file.arrayBuffer(),view=new DataView(buffer);if(buffer.byteLength<12||view.getUint32(0,true)!==0x41424154||view.getUint32(4,true)!==1)throw new Error('趋势索引损坏或版本不兼容。');trendBuffers.set(fileName,buffer);return buffer;}
function lookupRank(buffer,first,second){const view=new DataView(buffer),count=view.getUint32(8,true);let low=0,high=count-1,found=-1;while(low<=high){const middle=(low+high)>>>1,offset=12+middle*12,a=view.getUint32(offset,true),b=view.getUint32(offset+4,true);if(a===first&&b===second){found=middle;high=middle-1;}else if(a<first||(a===first&&b<second))low=middle+1;else high=middle-1;}if(found<0)return null;let best=Infinity;for(let position=found;position<count;position++){const offset=12+position*12;if(view.getUint32(offset,true)!==first||view.getUint32(offset+4,true)!==second)break;best=Math.min(best,view.getUint32(offset+8,true));}return Number.isFinite(best)?best:null;}
async function ensureTrend(report,token){let trendFile=report.trendFile||String(report.storageFile).replace(/\.jsonl\.gz$/,'.trend.bin');try{return{buffer:await readTrendIndex(trendFile),created:null};}catch(error){if(Number(report.storageVersion||1)>=2)throw error;self.postMessage({type:'trend-migration',token,label:report.label,reportIndex:0,reportTotal:1});const records=await loadLegacyReport(report.storageFile,token,0,1,'trend-migration-progress');trendFile=await saveLegacyTrend(report,records,token,trendFile);return{buffer:await readTrendIndex(trendFile),created:{id:report.id,trendFile}};}}

const analysisCache=new Map();
async function analysisMeta(report){if(analysisCache.has(report.storageFile))return analysisCache.get(report.storageFile);const directory=await reportDirectory(),file=await(await directory.getFileHandle(report.storageFile)).getFile(),header=await file.slice(0,HEADER_SIZE).arrayBuffer(),view=new DataView(header);if(view.getUint32(0,true)!==ANALYSIS_MAGIC||view.getUint32(4,true)!==2)throw new Error('分析数据格式损坏或版本不兼容。');const count=view.getUint32(8,true),blockSize=view.getUint32(12,true),indexOffset=Number(view.getBigUint64(16,true)),offsetCount=Math.ceil(count/blockSize)+1,indexBuffer=await file.slice(indexOffset,indexOffset+offsetCount*8).arrayBuffer(),iv=new DataView(indexBuffer),offsets=Array.from({length:offsetCount},(_,i)=>Number(iv.getBigUint64(i*8,true))),meta={file,count,blockSize,indexOffset,offsets};analysisCache.set(report.storageFile,meta);return meta;}
function parseRows(buffer,startOrdinal=0){const view=new DataView(buffer),rows=[];let offset=0,ordinal=startOrdinal;while(offset+24<=buffer.byteLength){const rank=view.getUint32(offset,true),click=view.getFloat64(offset+4,true),conversion=view.getFloat64(offset+12,true),length=view.getUint32(offset+20,true);if(offset+24+length>buffer.byteLength)break;const term=decoder.decode(new Uint8Array(buffer,offset+24,length));rows.push({ordinal,rank,term,searchKey:normalize(term),top3Click:click,top3Conversion:conversion});ordinal++;offset+=24+length;}return rows;}
async function readRowsByOrdinals(meta,ordinals){const groups=new Map(),result=new Array(ordinals.length);ordinals.forEach((ordinal,position)=>{const block=Math.floor(ordinal/meta.blockSize);if(!groups.has(block))groups.set(block,[]);groups.get(block).push({ordinal,position});});for(const [block,wanted] of groups){const buffer=await meta.file.slice(meta.offsets[block],meta.offsets[block+1]).arrayBuffer(),rows=parseRows(buffer,block*meta.blockSize),byOrdinal=new Map(rows.map(row=>[row.ordinal,row]));for(const item of wanted)result[item.position]=byOrdinal.get(item.ordinal);}return result.filter(Boolean);}
async function scanRows(meta,onRow,token){const reader=meta.file.slice(HEADER_SIZE,meta.indexOffset).stream().getReader();let carry=new Uint8Array(0),ordinal=0;while(true){const{value,done}=await reader.read();if(done)break;const data=new Uint8Array(carry.length+value.length);data.set(carry);data.set(value,carry.length);const view=new DataView(data.buffer),rows=[];let offset=0;while(offset+24<=data.length){const length=view.getUint32(offset+20,true);if(offset+24+length>data.length)break;const term=decoder.decode(data.subarray(offset+24,offset+24+length));rows.push({ordinal,rank:view.getUint32(offset,true),term,searchKey:normalize(term),top3Click:view.getFloat64(offset+4,true),top3Conversion:view.getFloat64(offset+12,true)});ordinal++;offset+=24+length;}carry=data.slice(offset);for(const row of rows)onRow(row);if(ordinal&&ordinal%50000<rows.length)self.postMessage({type:'query-progress',token,count:ordinal,total:meta.count});}if(carry.length)throw new Error('分析数据末尾不完整。');}

let queryCache=null;
function matchesBaseFilter(row,filters){return(!filters.keyword||row.searchKey.includes(filters.keyword))&&(filters.rankMin==null||row.rank>=filters.rankMin)&&(filters.rankMax==null||row.rank<=filters.rankMax)&&(filters.clickMax==null||row.top3Click<=filters.clickMax)&&(filters.conversionMax==null||row.top3Conversion<=filters.conversionMax);}
function matchesChangeFilter(row,filters,oldRank){const change=oldRank-row.rank;return(filters.changeMin==null||change>=filters.changeMin)&&(filters.changeMax==null||change<=filters.changeMax);}
async function queryPage(primary,comparison,filters,sorts,page,pageSize,queryKey,token){const meta=await analysisMeta(primary),created=[];let comparisonBuffer=null;if(comparison){const ensured=await ensureTrend(comparison,token);comparisonBuffer=ensured.buffer;if(ensured.created)created.push(ensured.created);}const hasFilters=Boolean(filters.keyword)||['rankMin','rankMax','clickMax','conversionMax','changeMin','changeMax'].some(key=>filters[key]!=null);const simpleSort=!sorts.length||(sorts.length===1&&sorts[0].key==='newRank');if(!hasFilters&&simpleSort){const descending=sorts.length&&sorts[0].direction==='desc',start=(page-1)*pageSize,end=Math.min(meta.count,start+pageSize);let ordinals;if(descending){const ascStart=Math.max(0,meta.count-end),ascEnd=Math.max(0,meta.count-start);ordinals=Array.from({length:Math.max(0,ascEnd-ascStart)},(_,i)=>ascEnd-1-i);}else ordinals=Array.from({length:Math.max(0,end-start)},(_,i)=>start+i);const rows=await readRowsByOrdinals(meta,ordinals);for(const row of rows){const pair=hashPair(row.searchKey),oldRank=comparisonBuffer?(lookupRank(comparisonBuffer,pair[0],pair[1])||0):0;row.newRank=row.rank;row.oldRank=oldRank;row.change=oldRank-row.rank;}return{rows,totalCount:meta.count,created};}
  if(!queryCache||queryCache.key!==queryKey){const matches=[],newRanks=new Uint32Array(meta.count),needOld=Boolean(comparisonBuffer)&&(filters.changeMin!=null||filters.changeMax!=null||sorts.some(sort=>sort.key==='oldRank'||sort.key==='change')),oldRanks=needOld?new Uint32Array(meta.count):null;await scanRows(meta,(row)=>{newRanks[row.ordinal]=row.rank;if(!matchesBaseFilter(row,filters))return;let oldRank=0;if(needOld){const pair=hashPair(row.searchKey);oldRank=lookupRank(comparisonBuffer,pair[0],pair[1])||0;oldRanks[row.ordinal]=oldRank;}if(matchesChangeFilter(row,filters,oldRank))matches.push(row.ordinal);},token);if(sorts.length){if(sorts.length===1&&sorts[0].key==='newRank'){if(sorts[0].direction==='desc')matches.reverse();}else matches.sort((left,right)=>{for(const sort of sorts){let a,b;if(sort.key==='newRank'){a=newRanks[left];b=newRanks[right];}else if(sort.key==='oldRank'){a=oldRanks?oldRanks[left]:0;b=oldRanks?oldRanks[right]:0;}else{a=(oldRanks?oldRanks[left]:0)-newRanks[left];b=(oldRanks?oldRanks[right]:0)-newRanks[right];}if(a!==b)return sort.direction==='asc'?a-b:b-a;}return newRanks[left]-newRanks[right]||left-right;});}queryCache={key:queryKey,matches,newRanks,oldRanks};}
  const start=(page-1)*pageSize,ordinals=queryCache.matches.slice(start,start+pageSize),rows=await readRowsByOrdinals(meta,ordinals);for(const row of rows){let oldRank=queryCache.oldRanks?queryCache.oldRanks[row.ordinal]:0;if(comparisonBuffer&&!queryCache.oldRanks){const pair=hashPair(row.searchKey);oldRank=lookupRank(comparisonBuffer,pair[0],pair[1])||0;}row.newRank=row.rank;row.oldRank=oldRank;row.change=oldRank-row.rank;}return{rows,totalCount:queryCache.matches.length,created};
}

async function queryTrends(reports,terms,token){const hashes=terms.map(key=>({key,pair:hashPair(key)})),ranks=Object.fromEntries(hashes.map(item=>[item.key,new Array(reports.length).fill(null)])),created=[];for(let reportIndex=0;reportIndex<reports.length;reportIndex++){const report=reports[reportIndex];let ensured;try{ensured=await ensureTrend(report,token);}catch(error){throw new Error(`${report.label}：${error.message||error}`);}if(ensured.created)created.push(ensured.created);for(const item of hashes)ranks[item.key][reportIndex]=lookupRank(ensured.buffer,item.pair[0],item.pair[1]);self.postMessage({type:'trend-progress',token,reportIndex,reportTotal:reports.length,label:report.label});}return{ranks,created};}

self.onmessage=async({data})=>{const{action='parse',file,index,total,token,site,storageFile,reports,terms,primary,comparison,filters,sorts,page,pageSize,queryKey}=data;try{
  if(action==='self-test'){const sha=new Sha256();sha.update(encoder.encode('abc'));self.postMessage({type:'self-test-result',token,sha:sha.hex()});return;}
  if(action==='load'){const records=await loadLegacyReport(storageFile,token,index,total);self.postMessage({type:'loaded',token,index,total,records});return;}
  if(action==='trend'){const result=await queryTrends(reports,terms,token);self.postMessage({type:'trend-result',token,...result});return;}
  if(action==='query-page'){const result=await queryPage(primary,comparison,filters,sorts,page,pageSize,queryKey,token);self.postMessage({type:'page-result',token,...result});return;}
  const result=await importReport(file,site,token,index,total);self.postMessage({type:'complete',token,index,total,...result});
}catch(error){const message=error?.message||String(error)||'未知错误';const type=action==='trend'?'trend-error':action==='query-page'?'page-error':'error';self.postMessage({type,token,index,total,message});}};
