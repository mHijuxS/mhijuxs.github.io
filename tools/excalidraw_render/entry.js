// esbuild entry: bundle Excalidraw export utilities + React into a single
// IIFE that exposes everything we need on `window`. The HTML harness then
// calls these from a Playwright page context.
import React from "react";
import ReactDOM from "react-dom";
import { createRoot } from "react-dom/client";
import {
  exportToBlob,
  exportToSvg,
  exportToCanvas,
  serializeAsJSON,
} from "@excalidraw/excalidraw";

window.React = React;
window.ReactDOM = ReactDOM;
window.createRoot = createRoot;
window.exportToBlob = exportToBlob;
window.exportToSvg = exportToSvg;
window.exportToCanvas = exportToCanvas;
window.serializeAsJSON = serializeAsJSON;
window.__excalidraw_ready__ = true;
