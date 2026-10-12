export type ArchitectureInputKind='TEXT_DOCUMENT'|'VECTOR_CAD'|'BIM'|'MESH_3D'|'RASTER_OR_SCAN'|'UNSUPPORTED';
export type ArchitectureInputCapability={kind:ArchitectureInputKind;extension:string;accepted:boolean;mode:'EXTRACT'|'IMPORT_GEOMETRY'|'REQUIRES_CONVERSION'|'REQUIRES_OCR'|'REJECT';limitations:string[]};
const ext=(name:string)=>{const m=name.toLowerCase().match(/\.([a-z0-9]+)$/);return m?m[1]:''};
export function architectureInputCapability(filename:string,mime=''):ArchitectureInputCapability{
 const e=ext(filename),text=new Set(['pdf','docx','xlsx','xls','txt','md','csv','json','xml','yaml','yml','log']);
 if(text.has(e))return {kind:'TEXT_DOCUMENT',extension:e,accepted:true,mode:'EXTRACT',limitations:e==='pdf'?['Text-layer extraction is supported; scanned/image-only diagrams require OCR or human transcription.','PDF drawing geometry is not treated as engineering CAD geometry.']:['Topology is extracted only from supported document content; relationships require evidence or review.']};
 if(e==='ifc')return {kind:'BIM',extension:e,accepted:false,mode:'REQUIRES_CONVERSION',limitations:['IFC/BIM geometry requires a dedicated parser before it can be represented as verified geometry.','Do not infer network connectivity from spatial adjacency.']};
 if(['dxf','dwg','step','stp','iges','igs'].includes(e))return {kind:'VECTOR_CAD',extension:e,accepted:false,mode:'REQUIRES_CONVERSION',limitations:['Native CAD parsing is not yet enabled. Convert through an approved geometry pipeline without discarding source provenance.']};
 if(['gltf','glb','obj'].includes(e))return {kind:'MESH_3D',extension:e,accepted:false,mode:'REQUIRES_CONVERSION',limitations:['3D mesh geometry alone does not establish infrastructure semantics, trust boundaries, or data flows.']};
 if(['png','jpg','jpeg','tif','tiff','webp'].includes(e)||mime.startsWith('image/'))return {kind:'RASTER_OR_SCAN',extension:e,accepted:false,mode:'REQUIRES_OCR',limitations:['Raster architecture diagrams require OCR/diagram interpretation and human verification before topology is accepted.']};
 return {kind:'UNSUPPORTED',extension:e,accepted:false,mode:'REJECT',limitations:['Unsupported architecture source format.']};
}
export function architectureFormatCatalog(){return [
 {formats:['PDF','DOCX','XLSX','XLS','TXT','MD','CSV','JSON','XML','YAML','LOG'],status:'TEXT_EXTRACTION'},
 {formats:['IFC'],status:'BIM_PARSER_REQUIRED'},
 {formats:['DXF','DWG','STEP','STP','IGES','IGS'],status:'CAD_CONVERSION_REQUIRED'},
 {formats:['GLTF','GLB','OBJ'],status:'3D_SEMANTIC_MAPPING_REQUIRED'},
 {formats:['PNG','JPG','JPEG','TIF','TIFF','WEBP'],status:'OCR_AND_HUMAN_REVIEW_REQUIRED'}
 ]};
