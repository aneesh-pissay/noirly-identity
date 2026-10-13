"use client";

import { useEffect, useState } from "react";
import { cn } from "@noirly-dev/ui";
import { IDENTITY_LOGO_URL } from "@/lib/brand";

/**
 * The Identity mark, inlined and tinted with the active theme.
 *
 * Same approach as Ledger / portfolio: proxy the SVG, drop the canvas, and
 * recolor fills to CSS variables so one asset works across palettes + schemes.
 */

const ACCENT = "var(--accent)";
const KNOCKOUT = "var(--brand-knockout, var(--bg))";

const PAINT_SERVERS = new Set([
  "mask",
  "clippath",
  "pattern",
  "lineargradient",
  "radialgradient",
  "filter",
  "marker",
  "symbol",
]);

function isNone(value: string | null | undefined): boolean {
  return value === "none" || value === "transparent";
}

function normaliseColour(value: string | null | undefined): string | null {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed || isNone(trimmed)) return null;
  return trimmed;
}

function fillOf(el: Element): string | null {
  return normaliseColour(
    el.getAttribute("fill") ?? el.getAttribute("style")?.match(/fill:\s*([^;]+)/i)?.[1],
  );
}

/** Luminance masks / clipPaths must keep their #fff/#000 paint. */
function isPaintServerDescendant(el: Element): boolean {
  let node: Element | null = el.parentElement;
  while (node) {
    const tag = node.tagName.toLowerCase();
    if (PAINT_SERVERS.has(tag)) return true;
    if (tag === "svg") return false;
    node = node.parentElement;
  }
  return false;
}

function isCanvasRect(el: Element, svg: Element): boolean {
  if (el.tagName.toLowerCase() !== "rect") return false;
  if (el.parentElement !== svg) return false;

  const w = Number.parseFloat(el.getAttribute("width") ?? "");
  const h = Number.parseFloat(el.getAttribute("height") ?? "");
  if (el.getAttribute("width") === "100%" || el.getAttribute("height") === "100%") return true;

  const viewBox = svg.getAttribute("viewBox")?.trim().split(/\s+/).map(Number);
  if (viewBox && viewBox.length >= 4) {
    const vbW = viewBox[2] ?? 0;
    const vbH = viewBox[3] ?? 0;
    if (w >= vbW * 0.9 && h >= vbH * 0.9) return true;
  }
  return false;
}

function themeSvgMarkup(raw: string): string | null {
  const doc = new DOMParser().parseFromString(raw.trim(), "image/svg+xml");
  const svg = doc.documentElement;
  if (svg.tagName.toLowerCase() !== "svg") return null;
  if (doc.querySelector("parsererror")) return null;

  svg.querySelectorAll("script,style,foreignObject,image,use,metadata").forEach((el) => el.remove());
  svg.querySelectorAll("*").forEach((el) => {
    for (const attr of [...el.attributes]) {
      if (/^on/i.test(attr.name) || /^xmlns:c2pa$/i.test(attr.name)) {
        el.removeAttribute(attr.name);
      }
    }
  });

  let canvasFill: string | null = null;
  svg.querySelectorAll("rect").forEach((rect) => {
    if (!isCanvasRect(rect, svg)) return;
    canvasFill ??= fillOf(rect);
    rect.remove();
  });

  const shapes = svg.querySelectorAll("g,path,circle,ellipse,polygon,polyline,rect,line");
  shapes.forEach((el) => {
    if (isPaintServerDescendant(el)) return;

    el.removeAttribute("class");
    el.removeAttribute("style");

    const fillAttr = el.getAttribute("fill");
    const fill = normaliseColour(fillAttr);
    const stroke = normaliseColour(el.getAttribute("stroke"));

    // Only rewrite an explicit fill. Unset fill stays unset so children can
    // inherit from a tinted <g fill="currentColor">.
    if (fillAttr !== null) {
      el.setAttribute("fill", fill ? (fill === canvasFill ? KNOCKOUT : ACCENT) : "none");
    }

    if (stroke) el.setAttribute("stroke", ACCENT);
  });

  svg.setAttribute("class", "brand-mark-inline");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("aria-hidden", "true");
  svg.removeAttribute("width");
  svg.removeAttribute("height");

  return svg.outerHTML;
}

function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return `${parts[0]![0]}${parts[1]![0]}`.toUpperCase();
  return (parts[0]?.slice(0, 2) ?? "NI").toUpperCase();
}

export interface BrandMarkProps {
  name?: string;
  src?: string;
  className?: string;
}

export function BrandMark({
  name = "Noirly Identity",
  src = IDENTITY_LOGO_URL,
  className,
}: BrandMarkProps) {
  const [markup, setMarkup] = useState<string | null>(null);
  const [palette, setPalette] = useState({ accent: "#c5a55a", background: "#101010" });
  useEffect(() => {
    const update = () => {
      const style = getComputedStyle(document.documentElement);
      setPalette({ accent: style.getPropertyValue("--accent").trim() || "#c5a55a", background: style.getPropertyValue("--brand-knockout").trim() || style.getPropertyValue("--bg").trim() || "#101010" });
    };
    update();
    const observer = new MutationObserver(update);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ["class", "style", "data-theme"] });
    return () => observer.disconnect();
  }, []);


  useEffect(() => {
    let active = true;

    fetch(`/api/brand-logo?src=${encodeURIComponent(src)}`)
      .then((res) => {
        if (!res.ok) throw new Error("logo fetch failed");
        return res.text();
      })
      .then((text) => {
        if (!active) return;
        const themed = themeSvgMarkup(text);
        if (!themed) throw new Error("not themeable");
        setMarkup(themed);
      })
      .catch(() => {
        /* initials fallback stays */
      });

    return () => {
      active = false;
    };
  }, [src]);

  if (!markup) {
    return (
      <span className={cn("brand-mark brand-mark--fallback h-9 w-9", className)} role="img" aria-label={name}>
        {initials(name)}
      </span>
    );
  }

  return (
    <span className={cn("brand-mark h-9 w-9", className)} role="img" aria-label={name}>
      {/* SVG stays in an image context, never the document DOM. */}
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img className="brand-mark-inner" src={`data:image/svg+xml,${encodeURIComponent(markup.replaceAll(KNOCKOUT, palette.background).replaceAll(ACCENT, palette.accent))}`} alt="" />
    </span>
  );
}
