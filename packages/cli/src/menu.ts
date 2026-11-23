// The start menu: move with the arrow keys, Enter runs the choice. Uses Node's own keypress events, no dependency.
import { emitKeypressEvents } from "node:readline";

/** Where the highlight goes for a key: arrows (or k and j) wrap around, Home and End jump. Pure. */
export function moved(key: string | undefined, at: number, count: number): number {
  if (key === "up" || key === "k") return (at + count - 1) % count;
  if (key === "down" || key === "j") return (at + 1) % count;
  return key === "home" ? 0 : key === "end" ? count - 1 : at;
}

/** The menu as lines of text, with the chosen row marked. The marker is a character, so it reads without colour too. Pure. */
export function frame(rows: string[], at: number, color: boolean): string[] {
  return rows.map((r, i) => (i !== at ? `    ${r}` : color ? `\x1b[38;2;11;110;79m  > \x1b[0m\x1b[1m${r}\x1b[0m` : `  > ${r}`));
}

/** Shows the menu and waits for a choice. Resolves with the row number, or null for q, Esc or Ctrl+C.
 *  Only call this when both stdin and stdout are a terminal. The terminal is put back as it was before resolving. */
export function choose(rows: string[], hint: string, color: boolean): Promise<number | null> {
  return new Promise((resolve) => {
    const { stdin, stdout } = process;
    let at = 0;
    const draw = (first: boolean) => {
      if (!first) stdout.write(`\x1b[${rows.length + 2}A`); // back up over the menu, the blank line and the hint
      for (const line of [...frame(rows, at, color), "", hint]) stdout.write(`\x1b[2K${line}\n`);
    };
    const done = (choice: number | null) => {
      stdin.off("keypress", onKey); stdin.setRawMode(false); stdin.pause();
      stdout.write("\x1b[?25h\n"); // show the cursor again
      resolve(choice);
    };
    const onKey = (_text: string, key: { name?: string; ctrl?: boolean }) => {
      if (key.name === "return" || key.name === "enter") return done(at);
      if (key.name === "q" || key.name === "escape" || (key.ctrl && key.name === "c")) return done(null);
      const next = moved(key.name, at, rows.length);
      if (next !== at) { at = next; draw(false); }
    };
    emitKeypressEvents(stdin);
    stdin.setRawMode(true); stdin.resume();
    stdout.write("\x1b[?25l"); // hide the cursor while the menu is up
    draw(true);
    stdin.on("keypress", onKey);
  });
}
