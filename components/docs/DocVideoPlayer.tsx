"use client";

import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent } from "react";
import { Captions, ListVideo, Maximize, Minimize, Pause, Play, VideoOff } from "lucide-react";
import type { ArticleMedia } from "@/lib/docs/types";

type Video = NonNullable<ArticleMedia["video"]>;

const SPEEDS = [0.5, 0.75, 1, 1.25, 1.5, 2];
/** Other parts of the page (chapter links, the transcript) seek the player with this event. */
export const SEEK_EVENT = "docs:seek";

export function seekDocVideo(seconds: number) {
  window.dispatchEvent(new CustomEvent<number>(SEEK_EVENT, { detail: seconds }));
}

/** Captions on or off, and playback speed, on the mounted <video>. */
function applyPlayback(element: HTMLVideoElement | null, captions: boolean, speed: number) {
  if (!element) return;
  const track = element.textTracks[0];
  if (track) track.mode = captions ? "showing" : "hidden";
  element.playbackRate = speed;
}

function clock(seconds: number) {
  const s = Math.max(0, Math.floor(seconds));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

/**
 * A native <video> with Noirly-styled controls: play/pause, seek, speed,
 * captions, chapters and fullscreen. Nothing downloads until Play is pressed
 * (preload="none" behind a poster), and it never autoplays.
 */
export function DocVideoPlayer({ title, video, unavailable, pending = false }: { title: string; video?: Video; unavailable?: string; pending?: boolean }) {
  const speedId = useId();
  const frameRef = useRef<HTMLDivElement>(null);
  const videoRef = useRef<HTMLVideoElement>(null);
  const [started, setStarted] = useState(false);
  const [playing, setPlaying] = useState(false);
  const [time, setTime] = useState(0);
  const [duration, setDuration] = useState(video?.duration ?? 0);
  const [speed, setSpeed] = useState(1);
  const [captions, setCaptions] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [chaptersOpen, setChaptersOpen] = useState(false);

  const play = useCallback(() => {
    setStarted(true);
    // The <video> mounts with its source on the first play.
    requestAnimationFrame(() => void videoRef.current?.play().catch(() => {}));
  }, []);

  const toggle = useCallback(() => {
    const element = videoRef.current;
    if (!started || !element) return play();
    if (element.paused) void element.play().catch(() => {});
    else element.pause();
  }, [play, started]);

  const seek = useCallback((seconds: number) => {
    setStarted(true);
    requestAnimationFrame(() => {
      const element = videoRef.current;
      if (!element) return;
      element.currentTime = Math.max(0, Math.min(seconds, element.duration || seconds));
      void element.play().catch(() => {});
    });
  }, []);

  useEffect(() => {
    const onSeek = (event: Event) => {
      seek((event as CustomEvent<number>).detail);
      frameRef.current?.scrollIntoView({ block: "center" });
    };
    window.addEventListener(SEEK_EVENT, onSeek);
    return () => window.removeEventListener(SEEK_EVENT, onSeek);
  }, [seek]);

  useEffect(() => {
    const onChange = () => setFullscreen(document.fullscreenElement === frameRef.current);
    document.addEventListener("fullscreenchange", onChange);
    return () => document.removeEventListener("fullscreenchange", onChange);
  }, []);

  useEffect(() => applyPlayback(videoRef.current, captions, speed), [captions, speed, started]);

  if (!video) {
    return (
      <div className="flex aspect-video w-full flex-col items-center justify-center gap-3 rounded-[var(--r-lg)] border border-dashed border-[var(--hairline)] bg-[var(--surface-2)]/40 p-6 text-center">
        <VideoOff size={22} aria-hidden className="text-[var(--muted-foreground)]" />
        <p className="text-sm font-medium text-[var(--foreground)]">{pending ? "Video coming soon" : "Video unavailable"}</p>
        <p className="max-w-md text-sm text-[var(--muted-foreground)]">
          {pending ? "A walkthrough of this feature will appear here once it's published." : unavailable ?? "This walkthrough hasn't been recorded yet. Run the docs pipeline to capture it."}
        </p>
      </div>
    );
  }

  const toggleFullscreen = () => {
    if (document.fullscreenElement) void document.exitFullscreen();
    else void frameRef.current?.requestFullscreen().catch(() => {});
  };

  const chapterAt = [...video.chapters].reverse().find((chapter) => chapter.start <= time + 0.25);

  const onKey = (event: KeyboardEvent<HTMLDivElement>) => {
    if ((event.target as HTMLElement).tagName === "INPUT" || (event.target as HTMLElement).tagName === "SELECT") return;
    if (event.key === " " || event.key === "k") { event.preventDefault(); toggle(); }
    else if (event.key === "ArrowRight") { event.preventDefault(); seek(time + 5); }
    else if (event.key === "ArrowLeft") { event.preventDefault(); seek(time - 5); }
    else if (event.key === "f") toggleFullscreen();
    else if (event.key === "c") setCaptions((on) => !on);
  };

  return (
    <div ref={frameRef} role="region" aria-label={`Video: ${title}`} onKeyDown={onKey} data-video-player
      className="group relative overflow-hidden rounded-[var(--r-lg)] border border-[var(--hairline)] bg-black">
      {started ? (
        <video
          ref={videoRef}
          className="aspect-video w-full bg-black"
          src={video.src}
          poster={video.poster}
          preload="metadata"
          playsInline
          onClick={toggle}
          onPlay={() => setPlaying(true)}
          onPause={() => setPlaying(false)}
          onTimeUpdate={(event) => setTime(event.currentTarget.currentTime)}
          onLoadedMetadata={(event) => setDuration(event.currentTarget.duration)}
          aria-label={title}
        >
          <track kind="captions" src={video.captions} srcLang="en" label="English" default />
        </video>
      ) : (
        <button type="button" onClick={play} aria-label={`Play video: ${title}`} className="relative block aspect-video w-full">
          {/* eslint-disable-next-line @next/next/no-img-element -- a poster the video replaces; nothing to optimise */}
          <img src={video.poster} alt="" className="absolute inset-0 h-full w-full object-cover opacity-80" />
          <span className="absolute inset-0 flex items-center justify-center">
            <span className="flex h-16 w-16 items-center justify-center rounded-full bg-[var(--accent)] text-[var(--accent-ink)] shadow-lg transition-transform group-hover:scale-105">
              <Play size={26} aria-hidden className="translate-x-0.5" />
            </span>
          </span>
          <span className="absolute bottom-3 right-3 rounded-md bg-black/70 px-2 py-0.5 font-mono text-xs text-white">{clock(video.duration)}</span>
        </button>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-white/10 bg-[var(--surface)] px-3 py-2 text-[var(--foreground)]">
        <button type="button" onClick={toggle} aria-label={playing ? "Pause" : "Play"}
          className="flex h-9 w-9 items-center justify-center rounded-lg hover:bg-[var(--surface-2)]">
          {playing ? <Pause size={16} aria-hidden /> : <Play size={16} aria-hidden />}
        </button>
        <span className="font-mono text-xs tabular-nums text-[var(--muted-foreground)]">{clock(time)} / {clock(duration)}</span>
        <input type="range" aria-label="Seek" min={0} max={duration || 0} step={0.1} value={Math.min(time, duration || 0)}
          onChange={(event) => seek(Number(event.target.value))}
          className="h-1 min-w-24 flex-1 cursor-pointer accent-[var(--accent)]" />
        <label className="sr-only" htmlFor={speedId}>Playback speed</label>
        <select id={speedId} value={speed} onChange={(event) => setSpeed(Number(event.target.value))}
          className="h-9 rounded-lg border border-[var(--hairline)] bg-[var(--bg)] px-2 font-mono text-xs">
          {SPEEDS.map((value) => <option key={value} value={value}>{value}×</option>)}
        </select>
        <button type="button" onClick={() => setCaptions((on) => !on)} aria-pressed={captions} aria-label="Captions"
          className={`flex h-9 w-9 items-center justify-center rounded-lg hover:bg-[var(--surface-2)] ${captions ? "text-[var(--accent)]" : "text-[var(--muted-foreground)]"}`}>
          <Captions size={16} aria-hidden />
        </button>
        {video.chapters.length > 1 ? (
          <div className="relative">
            <button type="button" onClick={() => setChaptersOpen((on) => !on)} aria-expanded={chaptersOpen} aria-label="Chapters"
              className="flex h-9 items-center gap-1.5 rounded-lg px-2 text-xs hover:bg-[var(--surface-2)]">
              <ListVideo size={16} aria-hidden />
              <span className="hidden max-w-36 truncate sm:inline">{chapterAt?.title ?? "Chapters"}</span>
            </button>
            {chaptersOpen ? (
              <ul aria-label="Chapters" className="absolute bottom-11 right-0 z-10 w-56 rounded-xl border border-[var(--hairline)] bg-[var(--surface)] p-1 shadow-xl">
                {video.chapters.map((chapter) => (
                  <li key={chapter.start}>
                    <button type="button" onClick={() => { seek(chapter.start); setChaptersOpen(false); }}
                      className={`flex w-full items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-left text-sm hover:bg-[var(--surface-2)] ${chapterAt === chapter ? "text-[var(--accent)]" : ""}`}>
                      <span>{chapter.title}</span>
                      <span className="font-mono text-[11px] text-[var(--muted-foreground)]">{clock(chapter.start)}</span>
                    </button>
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : null}
        <button type="button" onClick={toggleFullscreen} aria-label={fullscreen ? "Exit fullscreen" : "Fullscreen"}
          className="flex h-9 w-9 items-center justify-center rounded-lg hover:bg-[var(--surface-2)]">
          {fullscreen ? <Minimize size={16} aria-hidden /> : <Maximize size={16} aria-hidden />}
        </button>
      </div>
    </div>
  );
}
