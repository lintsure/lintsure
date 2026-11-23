// The menus: move with the arrow keys, Enter acts on the row. Uses Node's own keypress events, no dependency.
import { emitKeypressEvents } from "node:readline";

const BLUE = "\x1b[38;2;98;137;254m", GREEN = "\x1b[32m", OFF = "\x1b[0m";

/** Where the highlight goes for a key: arrows (or k and j) wrap around, Home and End jump. Pure. */
export function moved(key: string | undefined, at: number, count: number): number {
  if (key === "up" || key === "k") return (at + count - 1) % count;
  if (key === "down" || key === "j") return (at + 1) % count;
  return key === "home" ? 0 : key === "end" ? count - 1 : at;
}

/** The menu as lines of text, with the chosen row marked. The marker is a character, so it reads without colour too.
 *  The row is coloured, not bold: on a light theme bold text can come out grey, which made the choice look faded. Pure. */
export function frame(rows: string[], at: number, color: boolean): string[] {
  return rows.map((r, i) => (i !== at ? `    ${r}` : color ? `${BLUE}  > ${r}${OFF}` : `  > ${r}`));
}

/** A pick-any list as lines: a circle before each row, filled when picked (green in colour), then the closing rows,
 *  which have no circle. The filled and empty circles differ in shape, so the list reads without colour too. Pure. */
export function frameMany(rows: string[], picked: ReadonlySet<number>, closing: string[], at: number, color: boolean): string[] {
  const blue = (s: string) => (color ? `${BLUE}${s}${OFF}` : s);
  return [...rows, ...closing].map((r, i) => {
    const mark = i >= rows.length ? "" : picked.has(i) ? (color ? `${GREEN}●${OFF} ` : "● ") : "○ ";
    return i === at ? `${blue("  > ")}${mark}${blue(r)}` : `    ${mark}${r}`;
  });
}

/** Draws `count` rows and a hint, and hands each key to `act` until it returns an answer. The screen is redrawn after
 *  every key. q, Esc and Ctrl+C answer null. The terminal is put back as it was before resolving. */
function ask<T>(count: number, lines: (at: number) => string[], hint: string, act: (at: number, key: string | undefined) => { answer: T | null } | void): Promise<T | null> {
  return new Promise((resolve) => {
    const { stdin, stdout } = process;
    let at = 0;
    const draw = (first: boolean) => {
      if (!first) stdout.write(`\x1b[${count + 2}A`); // back up over the menu, the blank line and the hint
      for (const line of [...lines(at), "", hint]) stdout.write(`\x1b[2K${line}\n`);
    };
    const done = (answer: T | null) => {
      stdin.off("keypress", onKey); stdin.setRawMode(false); stdin.pause();
      stdout.write("\x1b[?25h\n"); // show the cursor again
      resolve(answer);
    };
    const onKey = (_text: string, key: { name?: string; ctrl?: boolean }) => {
      if (key.name === "q" || key.name === "escape" || (key.ctrl && key.name === "c")) return done(null);
      const result = act(at, key.name === "enter" ? "return" : key.name);
      if (result) return done(result.answer);
      at = moved(key.name, at, count);
      draw(false);
    };
    emitKeypressEvents(stdin);
    stdin.setRawMode(true); stdin.resume();
    stdout.write("\x1b[?25l"); // hide the cursor while the menu is up
    draw(true);
    stdin.on("keypress", onKey);
  });
}

/** Shows the menu and waits for a choice. Resolves with the row number, or null for q, Esc or Ctrl+C.
 *  Only call this when both stdin and stdout are a terminal. */
export function choose(rows: string[], hint: string, color: boolean): Promise<number | null> {
  return ask<number>(rows.length, (at) => frame(rows, at, color), hint, (at, key) => (key === "return" ? { answer: at } : undefined));
}

/** Shows a pick-any list. Enter (or Space) on a row picks it or lets it go; "a" picks all, or none when all are picked.
 *  Under the rows come a row that finishes, named by `finish` from the number picked, and Quit. Resolves with the
 *  picked row numbers (it may be empty), or null for Quit, q, Esc or Ctrl+C. Only call this at a terminal. */
export function chooseMany(rows: string[], finish: (picked: number) => string, hint: string, color: boolean): Promise<number[] | null> {
  const picked = new Set<number>();
  return ask<number[]>(rows.length + 2, (at) => frameMany(rows, picked, [finish(picked.size), "Quit"], at, color), hint, (at, key) => {
    if (key === "a") { if (picked.size === rows.length) picked.clear(); else rows.forEach((_, i) => picked.add(i)); return; }
    if (key !== "return" && key !== "space") return;
    if (at === rows.length) return { answer: [...picked].sort((x, y) => x - y) };
    if (at > rows.length) return { answer: null };
    if (!picked.delete(at)) picked.add(at);
  });
}
