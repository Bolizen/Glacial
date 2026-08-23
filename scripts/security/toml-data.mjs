// A deliberately small, data-only TOML parser for trusted verification code.
// It implements the TOML value/key forms used by Cargo manifests and lockfiles,
// including quoted/dotted keys and multiline strings, and fails closed on
// malformed or duplicate semantic fields.

export function parseTomlData(text) {
  const parser = new TomlParser(String(text));
  return parser.parse();
}

function mapping() { return Object.create(null); }

class TomlParser {
  constructor(text) { this.text = text; this.index = 0; this.root = mapping(); this.table = this.root; }

  parse() {
    while (this.skipSpaceAndComments(true), !this.end()) {
      if (this.peek() === "[") this.parseHeader();
      else this.assign(this.table, this.parseKeyPath(), this.requireValue());
      this.finishStatement();
    }
    return this.root;
  }

  end() { return this.index >= this.text.length; }
  peek(offset = 0) { return this.text[this.index + offset]; }
  error(message) { throw new Error(`invalid TOML near offset ${this.index}: ${message}`); }
  take(expected) { if (!this.text.startsWith(expected, this.index)) this.error(`expected ${expected}`); this.index += expected.length; }

  skipSpaceAndComments(newlines = false) {
    for (;;) {
      while (this.peek() === " " || this.peek() === "\t" || (newlines && (this.peek() === "\n" || this.peek() === "\r"))) this.index += 1;
      if (this.peek() !== "#") return;
      while (!this.end() && this.peek() !== "\n" && this.peek() !== "\r") this.index += 1;
    }
  }

  finishStatement() {
    this.skipSpaceAndComments(false);
    if (!this.end() && this.peek() !== "\n" && this.peek() !== "\r") this.error("unexpected trailing content");
    while (this.peek() === "\n" || this.peek() === "\r") this.index += 1;
  }

  parseHeader() {
    const array = this.text.startsWith("[[", this.index);
    this.take(array ? "[[" : "[");
    this.skipSpaceAndComments(false);
    const path = this.parseKeyPath();
    this.skipSpaceAndComments(false);
    this.take(array ? "]]" : "]");
    this.table = this.openTable(path, array);
  }

  parseKeyPath() {
    const parts = [];
    for (;;) {
      this.skipSpaceAndComments(false);
      parts.push(this.parseKey());
      this.skipSpaceAndComments(false);
      if (this.peek() !== ".") break;
      this.index += 1;
    }
    return parts;
  }

  parseKey() {
    if (this.peek() === '"' || this.peek() === "'") return this.parseString(false);
    const start = this.index;
    while (/[A-Za-z0-9_-]/.test(this.peek() ?? "")) this.index += 1;
    if (start === this.index) this.error("expected key");
    return this.text.slice(start, this.index);
  }

  requireValue() {
    this.skipSpaceAndComments(false);
    this.take("=");
    this.skipSpaceAndComments(false);
    return this.parseValue();
  }

  parseValue() {
    const char = this.peek();
    if (char === '"' || char === "'") return this.parseString(true);
    if (char === "[") return this.parseArray();
    if (char === "{") return this.parseInlineTable();
    const start = this.index;
    while (!this.end() && !/[\s,#\]}]/.test(this.peek())) this.index += 1;
    const token = this.text.slice(start, this.index);
    if (token === "true") return true;
    if (token === "false") return false;
    if (/^[+-]?\d(?:[\d_]*\d)?$/.test(token)) return Number(token.replaceAll("_", ""));
    if (!token || !/^[A-Za-z0-9_+.:TZ-]+$/.test(token)) this.error("unsupported bare value");
    return token;
  }

  parseString(allowMultiline) {
    const quote = this.peek();
    const multiline = this.text.startsWith(quote.repeat(3), this.index);
    if (multiline && !allowMultiline) this.error("multiline keys are not allowed");
    this.take(multiline ? quote.repeat(3) : quote);
    if (multiline && (this.peek() === "\n" || (this.peek() === "\r" && this.peek(1) === "\n"))) {
      if (this.peek() === "\r") this.index += 1;
      this.index += 1;
    }
    let value = "";
    const closing = multiline ? quote.repeat(3) : quote;
    while (!this.end() && !this.text.startsWith(closing, this.index)) {
      const char = this.peek();
      if (!multiline && (char === "\n" || char === "\r")) this.error("newline in string");
      if (quote === '"' && char === "\\") {
        this.index += 1;
        if (multiline && (this.peek() === "\n" || this.peek() === "\r")) {
          while (/[\s]/.test(this.peek() ?? "")) this.index += 1;
          continue;
        }
        const escaped = this.peek(); this.index += 1;
        const simple = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", '"': '"', "\\": "\\" };
        if (Object.hasOwn(simple, escaped)) value += simple[escaped];
        else if (escaped === "u" || escaped === "U") {
          const width = escaped === "u" ? 4 : 8;
          const digits = this.text.slice(this.index, this.index + width);
          if (!new RegExp(`^[0-9A-Fa-f]{${width}}$`).test(digits)) this.error("invalid unicode escape");
          value += String.fromCodePoint(Number.parseInt(digits, 16)); this.index += width;
        } else this.error("invalid escape");
      } else { value += char; this.index += 1; }
    }
    if (this.end()) this.error("unterminated string");
    this.take(closing);
    return value;
  }

  parseArray() {
    this.take("["); const values = [];
    for (;;) {
      this.skipSpaceAndComments(true);
      if (this.peek() === "]") { this.index += 1; return values; }
      values.push(this.parseValue());
      this.skipSpaceAndComments(true);
      if (this.peek() === ",") { this.index += 1; continue; }
      if (this.peek() !== "]") this.error("expected array delimiter");
    }
  }

  parseInlineTable() {
    this.take("{"); const value = mapping();
    for (;;) {
      this.skipSpaceAndComments(false);
      if (this.peek() === "}") { this.index += 1; return value; }
      this.assign(value, this.parseKeyPath(), this.requireValue());
      this.skipSpaceAndComments(false);
      if (this.peek() === ",") { this.index += 1; continue; }
      if (this.peek() !== "}") this.error("expected inline-table delimiter");
    }
  }

  assign(base, path, value) {
    let target = base;
    for (const part of path.slice(0, -1)) {
      if (!Object.hasOwn(target, part)) target[part] = mapping();
      if (!target[part] || Array.isArray(target[part]) || typeof target[part] !== "object") this.error("key conflicts with value");
      target = target[part];
    }
    const leaf = path.at(-1);
    if (Object.hasOwn(target, leaf)) this.error("duplicate key");
    target[leaf] = value;
  }

  openTable(path, array) {
    let target = this.root;
    for (const part of path.slice(0, -1)) {
      if (!Object.hasOwn(target, part)) target[part] = mapping();
      if (Array.isArray(target[part])) target = target[part].at(-1);
      else if (target[part] && typeof target[part] === "object") target = target[part];
      else this.error("table conflicts with value");
    }
    const leaf = path.at(-1);
    if (array) {
      if (!Object.hasOwn(target, leaf)) target[leaf] = [];
      if (!Array.isArray(target[leaf])) this.error("array table conflicts with value");
      const entry = mapping(); target[leaf].push(entry); return entry;
    }
    if (!Object.hasOwn(target, leaf)) target[leaf] = mapping();
    if (!target[leaf] || Array.isArray(target[leaf]) || typeof target[leaf] !== "object") this.error("table conflicts with value");
    return target[leaf];
  }
}
