// packages/core/watcher.mjs — Zero-Polling Reactive Ledger Event Watcher (Law 14, Milestone M1).
import { watch, statSync, openSync, readSync, closeSync, existsSync } from "node:fs";
import { dirname } from "node:path";
import { EventEmitter } from "node:events";
import { StringDecoder } from "node:string_decoder";

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
   * @param {number} [options.maxWaitMs=100] - Maximum delay before forced flush
   * @param {boolean} [options.fromBeginning=false] - Replay from byte 0
   * @param {number} [options.fromOffset] - Explicit byte offset to start from
   */
  constructor(ledgerPath, options = {}) {
    super();
    this.ledgerPath = ledgerPath;
    this.debounceMs =
      Number.isSafeInteger(options.debounceMs) && options.debounceMs >= 0
        ? options.debounceMs
        : 25;
    this.maxWaitMs =
      Number.isSafeInteger(options.maxWaitMs) && options.maxWaitMs >= this.debounceMs
        ? options.maxWaitMs
        : this.debounceMs * 4;
    this.fromBeginning = Boolean(options.fromBeginning);

    this.closed = false;
    this.fsWatcher = null;
    this.dirWatcher = null;
    this.debounceTimer = null;
    this.firstPendingMs = null;
    this.lastOffset = 0;
    this.remainder = "";
    this.decoder = new StringDecoder("utf8");
    this.lastError = null;

    if (Number.isSafeInteger(options.fromOffset) && options.fromOffset >= 0) {
      this.lastOffset = options.fromOffset;
    } else {
      this._initOffset();
    }
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
   * Safely dispatch errors without crashing unhandled EventEmitter.
   * @private
   */
  _handleError(err) {
    this.lastError = err;
    if (this.listenerCount("error") > 0) {
      this.emit("error", err);
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
        this._attachFileWatcher();
      } else {
        this._attachDirWatcher();
      }
    } catch (err) {
      this._handleError(err);
    }
  }

  /**
   * Attach watcher to parent directory until ledger file appears.
   * @private
   */
  _attachDirWatcher() {
    const dir = dirname(this.ledgerPath);
    if (!existsSync(dir)) return;

    try {
      if (this.dirWatcher) {
        try { this.dirWatcher.close(); } catch { /* mp-003-allow: best-effort close of a directory watcher we are about to replace */ }
      }
      this.dirWatcher = watch(dir, (eventType, filename) => {
        if (existsSync(this.ledgerPath)) {
          if (this.dirWatcher) {
            try { this.dirWatcher.close(); } catch { /* mp-003-allow: best-effort close before re-attaching after a ledger event */ }
            this.dirWatcher = null;
          }
          this._attachFileWatcher();
          this._scheduleRead();
        }
      });
      this.dirWatcher.on("error", (err) => this._handleError(err));
    } catch (err) {
      this._handleError(err);
    }
  }

  /**
   * Attach watcher directly to ledger file.
   * @private
   */
  _attachFileWatcher() {
    if (this.closed || !existsSync(this.ledgerPath)) return;
    try {
      if (this.fsWatcher) {
        try { this.fsWatcher.close(); } catch { /* mp-003-allow: best-effort close of the file watcher we are about to replace */ }
      }
      this.fsWatcher = watch(this.ledgerPath, (eventType) => {
        if (eventType === "rename" && !existsSync(this.ledgerPath)) {
          // File was deleted or moved; watch directory again
          if (this.fsWatcher) {
            try { this.fsWatcher.close(); } catch { /* mp-003-allow: best-effort close before falling back to the directory watcher */ }
            this.fsWatcher = null;
          }
          this._attachDirWatcher();
          return;
        }
        this._scheduleRead();
      });
      this.fsWatcher.on("error", (err) => this._handleError(err));
    } catch (err) {
      this._handleError(err);
    }
  }

  /**
   * Schedule a read after debounce delay to coalesce burst writes.
   * Capped by maxWaitMs to avoid starvation.
   * @private
   */
  _scheduleRead() {
    if (this.closed) return;
    const now = Date.now();
    if (this.firstPendingMs === null) {
      this.firstPendingMs = now;
    }

    if (now - this.firstPendingMs >= this.maxWaitMs) {
      if (this.debounceTimer) {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = null;
      }
      this.firstPendingMs = null;
      this.readNewEvents();
      return;
    }

    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
    }
    this.debounceTimer = setTimeout(() => {
      this.debounceTimer = null;
      this.firstPendingMs = null;
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
        this.decoder = new StringDecoder("utf8");
      }

      const bytesToRead = currentSize - this.lastOffset;
      if (bytesToRead <= 0) return [];

      fd = openSync(this.ledgerPath, "r");
      const buffer = Buffer.alloc(bytesToRead);
      const bytesRead = readSync(fd, buffer, 0, bytesToRead, this.lastOffset);
      this.lastOffset += bytesRead;

      // Decode bytes using StringDecoder to preserve split multi-byte characters
      const textChunk = this.decoder.write(buffer.subarray(0, bytesRead));
      const combined = this.remainder + textChunk;
      const lines = combined.split("\n");
      // Keep last incomplete segment in remainder
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
      this._handleError(err);
    } finally {
      if (fd !== null) {
        try { closeSync(fd); } catch { /* mp-003-allow: best-effort close of a descriptor opened only to read new ledger lines */ }
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
        this.removeListener("error", onError);
        if (signal) signal.removeEventListener("abort", onAbort);
      };

      const onError = (err) => {
        cleanup();
        reject(err);
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
      this.on("error", onError);
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
    this.firstPendingMs = null;
    if (this.fsWatcher) {
      try { this.fsWatcher.close(); } catch { /* mp-003-allow: best-effort close during shutdown; the watcher is being discarded */ }
      this.fsWatcher = null;
    }
    if (this.dirWatcher) {
      try { this.dirWatcher.close(); } catch { /* mp-003-allow: best-effort close during shutdown; the watcher is being discarded */ }
      this.dirWatcher = null;
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
