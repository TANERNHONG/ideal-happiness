// The waiting animations, by Settings → Animation pack:
// - transit: the MRT train pulls into a station (SQL), the SG Bus into a bus stop (Review);
// - desk: the cymbal monkey claps (SQL), filing cabinets are searched with a magnifying glass (Review);
// - commuter: in the first person, playing on your phone at an MRT platform (SQL) or a bus stop (Review).
// Settings → Animations (all, skip the ending, none) applies to both.

import { platformLoader } from "./commuter-platform";
import { busStopLoader } from "./commuter-busstop";
import { filesLoader, monkeyLoader } from "./desk-loaders";
import { state } from "./state";
import { busLoader, trainLoader, type Loader } from "./train-loader";

export type { Loader };
const pack = () => state.settings?.animation_pack ?? "transit";

/** While a SQL query runs (Data → SQL). */
export function sqlLoader(label: string): Loader {
  return pack() === "desk" ? monkeyLoader(label) : pack() === "commuter" ? platformLoader(label) : trainLoader(label);
}

/** While Review fetches the logs before and after an observation; the window labels the filing cabinets. */
export function reviewLoader(label: string, window: { before: number; after: number }): Loader {
  return pack() === "desk" ? filesLoader(label, window) : pack() === "commuter" ? busStopLoader(label) : busLoader(label);
}
