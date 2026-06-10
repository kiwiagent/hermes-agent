/**
 * elapsed.ts — the SHARED 1-second tick behind every running tool's live
 * elapsed counter (Epic 2.5). ONE module-level signal driven by ONE
 * setInterval for the whole app — never a timer per part. Refcounted: the
 * interval starts when the first subscriber mounts and is cleared when the
 * last one cleans up, so an idle transcript schedules zero wakeups.
 *
 * `useElapsedTick()` must be called inside a reactive scope that exists only
 * while ticking is needed (e.g. a component under `<Show when={running()}>`)
 * — its `onCleanup` is what releases the subscription. Read the returned
 * accessor in a TRACKING scope (JSX/memo/effect); the tick value itself is
 * meaningless — it exists to invalidate `Date.now()`-based computations.
 */
import { createSignal, onCleanup } from 'solid-js'

const [tick, setTick] = createSignal(0)

let subscribers = 0
let timer: ReturnType<typeof setInterval> | undefined

/** Subscribe the current reactive scope to the shared 1s tick (refcounted). */
export function useElapsedTick(): () => number {
  subscribers++
  timer ??= setInterval(() => setTick(t => t + 1), 1000)
  onCleanup(() => {
    subscribers--
    if (subscribers <= 0 && timer) {
      clearInterval(timer)
      timer = undefined
    }
  })
  return tick
}

/** Whole seconds since `startedAt` (clamped at 0) — pair with the tick. */
export function elapsedSeconds(startedAt: number): number {
  return Math.max(0, Math.floor((Date.now() - startedAt) / 1000))
}
