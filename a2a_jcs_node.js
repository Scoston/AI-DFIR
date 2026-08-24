#!/usr/bin/env node
"use strict";
/*
RFC 8785/JCS canonicalizer fallback.

JSON.parse guarantees numeric values use ECMAScript Number. JSON.stringify
provides the required ECMAScript primitive serialization. Object property names
are sorted with JavaScript's default UTF-16 code-unit ordering.
*/
let input="";
process.stdin.setEncoding("utf8");
process.stdin.on("data",d=>input+=d);
process.stdin.on("end",()=>{
  try{
    const obj=JSON.parse(input);
    function canon(v){
      if(v===null || typeof v==="boolean" || typeof v==="number" || typeof v==="string"){
        const s=JSON.stringify(v);
        if(s===undefined) throw new Error("unsupported primitive");
        return s;
      }
      if(Array.isArray(v)) return "["+v.map(canon).join(",")+"]";
      if(typeof v==="object"){
        const keys=Object.keys(v).sort();
        return "{"+keys.map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
      }
      throw new Error("unsupported JSON type");
    }
    process.stdout.write(canon(obj));
  }catch(e){
    process.stderr.write(String(e && e.stack || e));
    process.exit(2);
  }
});
