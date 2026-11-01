// packages/core/watcher.mjs — Zero-Polling Reactive Ledger Event Watcher (Law 14, Milestone M1).
import { watch, statSync, openSync, readSync, closeSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { EventEmitter } from "node:events";

/**
 * Reactive zero-polling ledger watcher.
 * Listens for file changes via operating system notifications (fs.watch)
 * and dispatches newly appended events with debounced coalescing.
 */
export class LedgerWatcher extends EventEmitter {
  /**
   * @param {string} ledgerPath - Path to events.jsonl
   * @param {object} [options]
   * @param {number} [options.debounceMs=25] - Debounce window in ms
   * @param {boolean} [options.fromBeginning=false] - Replay from byte 0
   */
  constructor(ledgerPath, options = {}) {
    super();
    this.ledgerPath = ledgerPath;
    this.debounceMs = Number.isSafeInteger(options.debounceMs) && options.debounceMs >= 0
      ? options.debounceMs
      : 25;
    this.fromBeginning = Boolean(options.fromBeginning);

    this.closed = false;
    this.fsWatcher = null;
    this.debounceTimer = null;
    this.lastOffset = 0;
    this.remainder = "";

    this._initOffset();
    this._startWatcher();
  }

  /**
   * Initialize byte offset.
   * @private
   */
  _initOffset() {
    if (this.fromBeginning) {
      this.lastOffset = 0;
      return;
    }
    try {
      if (existsSync(this.ledgerPath)) {
        const stats = statSync(this.ledgerPath);
        this.lastOffset = stats.size;
      } else {
        this.lastOffset = 0;
      }
    } catch {
      this.lastOffset = 0;
    }
  }

  /**
   * Start operating system file watcher.
   * @private
   */
  _startWatcher() {
    if (this.closed) return;

    try {
      if (existsSync(this.ledgerPath)) {
        this.fsWatcher = watch(this.ledgerPath, (eventType) => {
          this._scheduleRead();
        });
      } else {
        // Watch parent directory until events.jsonl is created
        const dir = dirname(this.ledgerPath);
        if (existsSync(dir)) {
          this.fsWatcher = watch(dir, (eventType, filename) => {
            if (existsSync(this.ledgerPath)) {
              if (this.fsWatcher) {
                try { this.fsWatcher.close(); } catch {}
              }
              this.fsWatcher = watch(this.ledgerPath, () => {
                this._scheduleRead();
              });
              this._scheduleRead();
            }
          });
        }
      }
    } catch (err) {
      this.emit("error", err);
    }
  }

  /**
   * Schedule a read after debounce delay to coalesce burst writes.
   * @private
   */
  _scheduleRead() {
    if (this.closed) return;
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.readNewEvents();
    }, this.debounceMs);
  }

  /**
   * Reads newly appended data from the file and emits events.
   *
   * @returns {object[]} parsed events emitted during this read
   */
  readNewEvents() {
    if (this.closed || !existsSync(this.ledgerPath)) return [];

    let fd = null;
    const emitted = [];
    try {
      const stats = statSync(this.ledgerPath);
      const currentSize = stats.size;

      // Handle file truncation / recreation
      if (currentSize < this.lastOffset) {
        this.lastOffset = 0;
        this.remainder = "";
      }

      const bytesToRead = currentSize - this.lastOffset;
      if (bytesToRead <= 0) return [];

      fd = openSync(this.ledgerPath, "r");
      const buffer = Buffer.alloc(bytesToRead);
      const bytesRead = readSync(fd, buffer, 0, bytesToRead, this.lastOffset);
      this.lastOffset += bytesRead;

      const chunk = this.remainder + buffer.toString("utf8", 0, bytesRead);
      const lines = chunk.split("\n");
      // Keep last partial segment in remainder
      this.remainder = lines.pop() ?? "";

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const parsed = JSON.parse(trimmed);
          emitted.push(parsed);
          this.emit("event", parsed);
          if (parsed && typeof parsed.type === "string") {
            this.emit(parsed.type, parsed);
          }
        } catch (parseErr) {
          this.emit("raw_line", trimmed, parseErr);
        }
      }
    } catch (err) {
      this.emit("error", err);
    } finally {
      if (fd !== null) {
        try { closeSync(fd); } catch {}
      }
    }

    return emitted;
  }

  /**
   * Wait for an event satisfying a predicate.
   *
   * @param {(event: object) => boolean} predicate
   * @param {object} [waitOptions]
   * @param {number} [waitOptions.timeoutMs=10000]
   * @param {AbortSignal} [waitOptions.signal]
   * @returns {Promise<object>}
   */
  waitFor(predicate, waitOptions = {}) {
    const timeoutMs = waitOptions.timeoutMs ?? 10000;
    const signal = waitOptions.signal;

    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        return reject(new Error("Aborted"));
      }

      let timer = null;

      const cleanup = () => {
        if (timer) clearTimeout(timer);
        this.removeListener("event", listener);
        if (signal) signal.removeEventListener("abort", onAbort);
      };

      const onAbort = () => {
        cleanup();
        reject(new Error("Aborted"));
      };

      const listener = (event) => {
        try {
          if (predicate(event)) {
            cleanup();
            resolve(event);
          }
        } catch (err) {
          cleanup();
          reject(err);
        }
      };

      if (timeoutMs > 0) {
        timer = setTimeout(() => {
          cleanup();
          reject(new Error(`Timeout waiting for event after ${timeoutMs}ms`));
        }, timeoutMs);
      }

      if (signal) {
        signal.addEventListener("abort", onAbort, { once: true });
      }

      this.on("event", listener);
    });
  }

  /**
   * Closes the watcher and releases resources.
   */
  close() {
    this.closed = true;
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = null;
    }
    if (this.fsWatcher) {
      try { this.fsWatcher.close(); } catch {}
      this.fsWatcher = null;
    }
    this.removeAllListeners();
  }
}

/**
 * Creates a zero-polling reactive event watcher on a ledger events.jsonl file.
 *
 * @param {string} ledgerPath - Absolute path to events.jsonl
 * @param {object} [options]
 * @returns {LedgerWatcher}
 */
export function createLedgerWatcher(ledgerPath, options = {}) {
  return new LedgerWatcher(ledgerPath, options);
}

/**
 * Wait for a specific event to appear in the ledger.
 *
 * @param {string} ledgerPath
 * @param {(event: object) => boolean} predicate
 * @param {object} [options]
 * @returns {Promise<object>}
 */
export async function waitForLedgerEvent(ledgerPath, predicate, options = {}) {
  const watcher = new LedgerWatcher(ledgerPath, options);
  try {
    return await watcher.waitFor(predicate, options);
  } finally {
    watcher.close();
  }
}
