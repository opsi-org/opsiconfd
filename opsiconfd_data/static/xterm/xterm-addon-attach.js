!function(s,t){"object"==typeof exports&&"object"==typeof module?module.exports=t():"function"==typeof define&&define.amd?define([],t):"object"==typeof exports?exports.AttachAddon=t():s.AttachAddon=t()}(self,(function(){return(()=>{"use strict";var s={};return(()=>{var t=s;function e(s,t,e){return s.addEventListener(t,e),{dispose:()=>{e&&s.removeEventListener(t,e)}}}Object.defineProperty(t,"__esModule",{value:!0}),t.AttachAddon=void 0,t.AttachAddon=class{constructor(s,t){this._disposables=[],this._socket=s,this._socket.binaryType="arraybuffer",this._bidirectional=!(t&&!1===t.bidirectional)}activate(s){this._disposables.push(e(this._socket,"message",(t=>{const e=t.data;s.write("string"==typeof e?e:new Uint8Array(e))}))),this._bidirectional&&(this._disposables.push(s.onData((s=>this._sendData(s)))),this._disposables.push(s.onBinary((s=>this._sendBinary(s))))),this._disposables.push(e(this._socket,"close",(()=>this.dispose()))),this._disposables.push(e(this._socket,"error",(()=>this.dispose())))}dispose(){for(const s of this._disposables)s.dispose()}_sendData(s){1===this._socket.readyState&&this._socket.send(s)}_sendBinary(s){if(1!==this._socket.readyState)return;const t=new Uint8Array(s.length);for(let e=0;e<s.length;++e)t[e]=255&s.charCodeAt(e);this._socket.send(t)}}})(),s})()}));
//# sourceMappingURL=xterm-addon-attach.js.map