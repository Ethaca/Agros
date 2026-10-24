/**
 * A pragmatic Java source reader for `argos init` (no dependencies, never runs code).
 *
 * Lexer: drops comments, keeps string/char/text-block literals as single tokens (so braces or "//" inside strings
 * never confuse the structure), tracks line numbers.
 * Parser: type declarations (class/interface/enum/record/@interface, nested), their annotations, fields, record
 * components, constructors and methods with parameter lists, and method bodies as token ranges (brace matching).
 * It is not a full Java grammar: anything it does not understand inside a body is skipped, never guessed.
 */

export type TokKind = "id" | "str" | "chr" | "num" | "op";
export interface Tok {
  k: TokKind;
  v: string;
  line: number;
}

const ID_START = /[A-Za-z_$]/;
const ID_PART = /[A-Za-z0-9_$]/;
const MULTI_OPS = ["...", "::", "->", "==", "!=", "&&", "||", "<=", "+=", "-="];

export function lex(src: string): Tok[] {
  const out: Tok[] = [];
  let i = 0;
  let line = 1;
  const n = src.length;
  while (i < n) {
    const c = src[i]!;
    if (c === "\n") {
      line++;
      i++;
      continue;
    }
    if (c === " " || c === "\t" || c === "\r" || c === "\f") {
      i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      while (i < n && src[i] !== "\n") i++;
      continue;
    }
    if (c === "/" && src[i + 1] === "*") {
      i += 2;
      while (i < n && !(src[i] === "*" && src[i + 1] === "/")) {
        if (src[i] === "\n") line++;
        i++;
      }
      i += 2;
      continue;
    }
    if (c === '"' && src.startsWith('"""', i)) {
      const start = line;
      i += 3;
      let v = "";
      while (i < n && !src.startsWith('"""', i)) {
        if (src[i] === "\\" && i + 1 < n) {
          v += src[i + 1];
          i += 2;
          continue;
        }
        if (src[i] === "\n") line++;
        v += src[i];
        i++;
      }
      i += 3;
      out.push({ k: "str", v, line: start });
      continue;
    }
    if (c === '"' || c === "'") {
      const start = line;
      i++;
      let v = "";
      while (i < n && src[i] !== c && src[i] !== "\n") {
        if (src[i] === "\\" && i + 1 < n) {
          const e = src[i + 1]!;
          v += e === "n" ? "\n" : e === "t" ? "\t" : e;
          i += 2;
          continue;
        }
        v += src[i];
        i++;
      }
      i++;
      out.push({ k: c === '"' ? "str" : "chr", v, line: start });
      continue;
    }
    if (ID_START.test(c)) {
      let j = i + 1;
      while (j < n && ID_PART.test(src[j]!)) j++;
      out.push({ k: "id", v: src.slice(i, j), line });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i + 1;
      while (j < n && /[0-9A-Za-z_.]/.test(src[j]!)) j++;
      out.push({ k: "num", v: src.slice(i, j), line });
      i = j;
      continue;
    }
    const op = MULTI_OPS.find((o) => src.startsWith(o, i));
    if (op) {
      out.push({ k: "op", v: op, line });
      i += op.length;
      continue;
    }
    out.push({ k: "op", v: c, line });
    i++;
  }
  return out;
}

export interface Annotation {
  /** Simple name (last segment): `org.x.GetMapping` -> `GetMapping`. */
  name: string;
  /** Tokens between the parentheses (empty without arguments). */
  args: Tok[];
  line: number;
}

export interface JParam {
  name: string;
  type: string;
  annotations: Annotation[];
}

export interface JField {
  name: string;
  type: string;
  annotations: Annotation[];
  modifiers: string[];
  line: number;
  /** Initializer tokens (after `=`), if any. */
  init: Tok[];
}

export interface JMethod {
  name: string;
  returnType: string;
  annotations: Annotation[];
  modifiers: string[];
  params: JParam[];
  constructor: boolean;
  line: number;
  /** Body tokens without the outer braces (empty for abstract/interface methods). */
  body: Tok[];
}

export interface JType {
  kind: "class" | "interface" | "enum" | "record" | "annotation";
  name: string;
  annotations: Annotation[];
  /** Text after `extends` (generic arguments included). */
  extends: string;
  implements: string;
  fields: JField[];
  methods: JMethod[];
  /** Record components. */
  components: JParam[];
  enumConstants: string[];
  types: JType[];
  line: number;
  /** Repo-relative file. */
  file: string;
  /** Enclosing type name for nested types. */
  outer?: string;
}

export interface JFile {
  file: string;
  pkg: string;
  imports: string[];
  types: JType[];
}

const MODIFIERS = new Set([
  "public",
  "private",
  "protected",
  "static",
  "final",
  "abstract",
  "default",
  "synchronized",
  "native",
  "transient",
  "volatile",
  "sealed",
  "strictfp",
]);
const TYPE_KW = new Set(["class", "interface", "enum", "record"]);

class Parser {
  i = 0;
  constructor(
    readonly t: Tok[],
    readonly file: string,
  ) {}

  peek(o = 0): Tok | undefined {
    return this.t[this.i + o];
  }
  is(v: string, o = 0): boolean {
    const x = this.t[this.i + o];
    return !!x && x.v === v && (x.k === "op" || x.k === "id");
  }

  /** Index just past the bracket that closes the one at `from` (`(`, `{`, `[`, `<`). */
  close(from: number): number {
    const open = this.t[from]!.v;
    const shut = open === "(" ? ")" : open === "{" ? "}" : open === "[" ? "]" : ">";
    let d = 0;
    for (let j = from; j < this.t.length; j++) {
      const x = this.t[j]!;
      if (x.k !== "op") continue;
      if (x.v === open) d++;
      else if (x.v === shut) {
        d--;
        if (d === 0) return j + 1;
      } else if (open === "<" && (x.v === ";" || x.v === "{" || x.v === ")")) return j; // not a generic after all
    }
    return this.t.length;
  }

  annotation(): Annotation {
    const line = this.peek()!.line;
    this.i++; // @
    let name = this.peek()?.v ?? "";
    this.i++;
    while (this.is(".") && this.peek(1)?.k === "id") {
      name = this.peek(1)!.v;
      this.i += 2;
    }
    let args: Tok[] = [];
    if (this.is("(")) {
      const end = this.close(this.i);
      args = this.t.slice(this.i + 1, end - 1);
      this.i = end;
    }
    return { name, args, line };
  }

  annotations(): Annotation[] {
    const out: Annotation[] = [];
    while (this.is("@") && !this.is("interface", 1)) out.push(this.annotation());
    return out;
  }

  modifiers(): string[] {
    const out: string[] = [];
    for (;;) {
      const x = this.peek();
      if (!x || x.k !== "id") break;
      if (MODIFIERS.has(x.v)) {
        out.push(x.v);
        this.i++;
      } else if (x.v === "non" && this.is("-", 1) && this.peek(2)?.v === "sealed") {
        this.i += 3;
      } else break;
    }
    return out;
  }

  /** A type reference: `a.b.C<D<E>>[]...`; returns its text. */
  type(): string {
    let s = "";
    while (this.is("@")) this.annotation(); // type-use annotations
    const x = this.peek();
    if (!x || x.k !== "id") return s;
    s += x.v;
    this.i++;
    for (;;) {
      if (this.is(".") && this.peek(1)?.k === "id") {
        s += "." + this.peek(1)!.v;
        this.i += 2;
      } else if (this.is("<")) {
        const end = this.close(this.i);
        s += this.t
          .slice(this.i, end)
          .map((y) => y.v)
          .join("")
          .replace(/,/g, ", ");
        this.i = end;
      } else if (this.is("[") && this.is("]", 1)) {
        s += "[]";
        this.i += 2;
      } else if (this.is("...")) {
        s += "...";
        this.i++;
      } else break;
    }
    return s;
  }

  params(): JParam[] {
    // at "("
    const end = this.close(this.i);
    const out: JParam[] = [];
    this.i++;
    while (this.i < end - 1) {
      const annotations = this.annotations();
      this.modifiers();
      const type = this.type();
      const name = this.peek()?.k === "id" ? this.peek()!.v : "";
      if (type && name) out.push({ name, type, annotations });
      // skip to the next top-level comma
      let d = 0;
      while (this.i < end - 1) {
        const x = this.peek()!;
        if (x.k === "op" && (x.v === "(" || x.v === "<" || x.v === "[" || x.v === "{")) d++;
        else if (x.k === "op" && (x.v === ")" || x.v === ">" || x.v === "]" || x.v === "}")) d--;
        else if (d <= 0 && x.k === "op" && x.v === ",") {
          this.i++;
          break;
        }
        this.i++;
      }
    }
    this.i = end;
    return out;
  }

  typeDecl(annotations: Annotation[], outer?: string): JType | undefined {
    let kind: JType["kind"];
    if (this.is("@") && this.is("interface", 1)) {
      kind = "annotation";
      this.i += 2;
    } else {
      kind = this.peek()!.v as JType["kind"];
      this.i++;
    }
    const nameTok = this.peek();
    if (!nameTok || nameTok.k !== "id") return undefined;
    this.i++;
    const ty: JType = {
      kind,
      name: nameTok.v,
      annotations,
      extends: "",
      implements: "",
      fields: [],
      methods: [],
      components: [],
      enumConstants: [],
      types: [],
      line: nameTok.line,
      file: this.file,
      ...(outer ? { outer } : {}),
    };
    if (this.is("<")) this.i = this.close(this.i);
    if (kind === "record" && this.is("(")) ty.components = this.params();
    let clause: "extends" | "implements" | "permits" | undefined;
    const parts: Record<string, string[]> = { extends: [], implements: [], permits: [] };
    while (this.i < this.t.length && !this.is("{")) {
      const x = this.peek()!;
      if (x.k === "id" && (x.v === "extends" || x.v === "implements" || x.v === "permits")) clause = x.v;
      else if (clause) parts[clause]!.push(x.v);
      this.i++;
    }
    ty.extends = parts.extends!.join("");
    ty.implements = parts.implements!.join("");
    if (!this.is("{")) return ty;
    const end = this.close(this.i);
    this.i++;
    this.body(ty, end - 1);
    this.i = end;
    return ty;
  }

  /** Members of a type body, up to (not including) the closing brace at `end`. */
  body(ty: JType, end: number): void {
    if (ty.kind === "enum") {
      // constants: NAME [(args)] [{body}] , ... ; or }
      while (this.i < end) {
        this.annotations();
        const x = this.peek();
        if (!x || x.k !== "id") break;
        ty.enumConstants.push(x.v);
        this.i++;
        if (this.is("(")) this.i = this.close(this.i);
        if (this.is("{")) this.i = this.close(this.i);
        if (this.is(",")) {
          this.i++;
          continue;
        }
        break;
      }
      if (this.is(";")) this.i++;
    }
    while (this.i < end) {
      if (this.is(";")) {
        this.i++;
        continue;
      }
      const start = this.i;
      const annotations = this.annotations();
      const modifiers = this.modifiers();
      if (this.is("@") && this.is("interface", 1)) {
        const nt = this.typeDecl(annotations, ty.name);
        if (nt) ty.types.push(nt);
        continue;
      }
      const x = this.peek();
      if (!x) break;
      if (x.k === "id" && TYPE_KW.has(x.v) && this.peek(1)?.k === "id") {
        const nt = this.typeDecl(annotations, ty.name);
        if (nt) ty.types.push(nt);
        continue;
      }
      if (this.is("{")) {
        this.i = this.close(this.i); // initializer block
        continue;
      }
      if (this.is("<")) this.i = this.close(this.i); // generic method type parameters
      const line = this.peek()?.line ?? x.line;
      // compact record constructor: Name {
      if (ty.kind === "record" && this.peek()?.v === ty.name && this.is("{", 1)) {
        this.i++;
        this.i = this.close(this.i);
        continue;
      }
      // constructor: Name (
      if (this.peek()?.v === ty.name && this.is("(", 1)) {
        this.i++;
        const params = this.params();
        const body = this.methodBody(end);
        ty.methods.push({ name: ty.name, returnType: "", annotations, modifiers, params, constructor: true, line, body });
        continue;
      }
      const type = this.type();
      const nameTok = this.peek();
      if (!type || !nameTok || nameTok.k !== "id") {
        this.skipStatement(end);
        if (this.i === start) this.i++;
        continue;
      }
      this.i++;
      if (this.is("(")) {
        const params = this.params();
        const body = this.methodBody(end);
        ty.methods.push({ name: nameTok.v, returnType: type, annotations, modifiers, params, constructor: false, line: nameTok.line, body });
        continue;
      }
      // field(s): T a = ..., b;
      let names = [{ name: nameTok.v, line: nameTok.line }];
      const initStart = this.is("=") ? this.i + 1 : -1;
      const stop = this.skipStatement(end);
      const init = initStart >= 0 ? this.t.slice(initStart, stop) : [];
      for (const f of names) ty.fields.push({ name: f.name, type, annotations, modifiers, line: f.line, init });
      names = [];
    }
  }

  /** After a parameter list: skip `throws ...` and read `{ body }` or `;` / `default value;`. */
  methodBody(end: number): Tok[] {
    while (this.i < end && !this.is("{") && !this.is(";")) this.i++;
    if (this.is(";")) {
      this.i++;
      return [];
    }
    if (!this.is("{")) return [];
    const close = this.close(this.i);
    const body = this.t.slice(this.i + 1, close - 1);
    this.i = close;
    return body;
  }

  /** Skip to the `;` that ends a field/statement at depth 0 (initializers may hold lambdas/array braces). Returns the index of the `;`. */
  skipStatement(end: number): number {
    let d = 0;
    while (this.i < end) {
      const x = this.peek()!;
      if (x.k === "op") {
        if (x.v === "(" || x.v === "{" || x.v === "[") d++;
        else if (x.v === ")" || x.v === "}" || x.v === "]") d--;
        else if (x.v === ";" && d <= 0) {
          const at = this.i;
          this.i++;
          return at;
        }
      }
      this.i++;
    }
    return this.i;
  }

  file_(): JFile {
    let pkg = "";
    const imports: string[] = [];
    const types: JType[] = [];
    while (this.i < this.t.length) {
      if (this.is("package")) {
        this.i++;
        const parts: string[] = [];
        while (this.i < this.t.length && !this.is(";")) parts.push(this.t[this.i++]!.v);
        pkg = parts.join("");
        this.i++;
        continue;
      }
      if (this.is("import")) {
        this.i++;
        const parts: string[] = [];
        while (this.i < this.t.length && !this.is(";")) parts.push(this.t[this.i++]!.v);
        imports.push(parts.join("").replace(/^static/, "static "));
        this.i++;
        continue;
      }
      if (this.is(";")) {
        this.i++;
        continue;
      }
      const before = this.i;
      const annotations = this.annotations();
      this.modifiers();
      if ((this.is("@") && this.is("interface", 1)) || (this.peek()?.k === "id" && TYPE_KW.has(this.peek()!.v))) {
        const ty = this.typeDecl(annotations);
        if (ty) types.push(ty);
        continue;
      }
      if (this.i === before) this.i++;
    }
    return { file: this.file, pkg, imports, types };
  }
}

export function parseJava(src: string, file: string): JFile {
  return new Parser(lex(src), file).file_();
}

/** All types in a file, nested ones included. */
export function allTypes(f: JFile): JType[] {
  const out: JType[] = [];
  const visit = (t: JType) => {
    out.push(t);
    t.types.forEach(visit);
  };
  f.types.forEach(visit);
  return out;
}

// ---------------------------------------------------------------- annotation helpers

export const ann = (as: Annotation[], ...names: string[]): Annotation | undefined => as.find((a) => names.includes(a.name));

/** Split annotation arguments into `name -> tokens` (the unnamed single value is "value"). */
export function annAttrs(a: Annotation): Map<string, Tok[]> {
  const out = new Map<string, Tok[]>();
  const parts: Tok[][] = [[]];
  let d = 0;
  for (const x of a.args) {
    if (x.k === "op" && (x.v === "(" || x.v === "{" || x.v === "[")) d++;
    if (x.k === "op" && (x.v === ")" || x.v === "}" || x.v === "]")) d--;
    if (d === 0 && x.k === "op" && x.v === ",") parts.push([]);
    else parts[parts.length - 1]!.push(x);
  }
  for (const p of parts) {
    if (!p.length) continue;
    if (p[0]!.k === "id" && p[1]?.v === "=" && p[1].k === "op") out.set(p[0]!.v, p.slice(2));
    else out.set("value", [...(out.get("value") ?? []), ...p]);
  }
  return out;
}

/** String values of an annotation attribute (`"a"`, `{"a", "b"}`, constant references resolved through `consts`). */
export function annStrings(a: Annotation, attrs: string[] = ["value", "path"], consts?: Map<string, string>): string[] {
  const m = annAttrs(a);
  const out: string[] = [];
  for (const name of attrs) {
    const toks = m.get(name);
    if (!toks) continue;
    for (let i = 0; i < toks.length; i++) {
      const x = toks[i]!;
      if (x.k === "str") {
        // "a" + "b" concatenation
        let s = x.v;
        while (toks[i + 1]?.v === "+" && toks[i + 2]?.k === "str") {
          s += toks[i + 2]!.v;
          i += 2;
        }
        out.push(s);
      } else if (x.k === "id" && consts && toks[i + 1]?.v !== "." && consts.has(x.v)) out.push(consts.get(x.v)!);
    }
  }
  return out;
}

/** Identifiers in an attribute, e.g. `method = {RequestMethod.GET, RequestMethod.POST}` -> [..., "GET", "POST"]. */
export function annIds(a: Annotation, attr: string): string[] {
  return (annAttrs(a).get(attr) ?? []).filter((x) => x.k === "id").map((x) => x.v);
}

export const tokText = (ts: Tok[]): string =>
  ts
    .map((x) => (x.k === "str" ? JSON.stringify(x.v) : x.k === "chr" ? `'${x.v}'` : x.v))
    .join(" ")
    .replace(/ ?([.()\[\]]) ?/g, "$1");

/** Simple name of a (possibly generic, qualified) type: `java.util.List<Foo>` -> `List`. */
export const simpleType = (t: string): string => t.replace(/<.*$/, "").replace(/\[\]|\.\.\./g, "").split(".").pop() ?? t;

/** Generic arguments at top level: `Page<Map<A, B>>` -> ["Map<A, B>"]; `JpaRepository<User, UUID>` -> ["User", "UUID"]. */
export function typeArgs(t: string): string[] {
  const open = t.indexOf("<");
  if (open < 0) return [];
  const inner = t.slice(open + 1, t.lastIndexOf(">"));
  const out: string[] = [];
  let d = 0;
  let cur = "";
  for (const c of inner) {
    if (c === "<") d++;
    if (c === ">") d--;
    if (c === "," && d === 0) {
      out.push(cur.trim());
      cur = "";
    } else cur += c;
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}
