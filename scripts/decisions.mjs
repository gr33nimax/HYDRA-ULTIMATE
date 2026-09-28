#!/usr/bin/env node
/** Dependency-free ADR-light journal CLI. */
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const VALID_STATUSES = new Set(["proposed", "accepted"]);
const FILE_RE = /^(\d{4})-([a-z0-9]+(?:-[a-z0-9]+)*)\.md$/;
const SECTION_RE = /^## ([^\n]+)\s*$/gm;
const HELP = `Usage:
  node scripts/decisions.mjs scan
  node scripts/decisions.mjs add --title <text> --context <text> --decision <text> --consequences <text> --link <path> [--link <path> ...]
  node scripts/decisions.mjs review NNNN
  node scripts/decisions.mjs approve NNNN

Exit codes: 0 success, 1 validation or filesystem error, 2 invalid command or arguments.`;

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(scriptDir, "..");
const decisionsDir = path.join(root, ".kiro", "decisions");
const readmePath = path.join(decisionsDir, "README.md");
const lockPath = path.join(decisionsDir, ".decisions.lock");

function fail(message, code = 1) {
  process.stderr.write(`${message}\n`);
  process.exitCode = code;
}

function requireText(value, name) {
  if (typeof value !== "string" || !value.trim() || /[\r\n]/.test(value)) {
    throw new Error(`${name} must be a non-empty single-line value`);
  }
  return value.trim();
}

function slugify(title) {
  const slug = title
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) {
    throw new Error("title must produce a non-empty kebab-case slug");
  }
  return slug;
}

function safeLink(value) {
  const link = requireText(value, "link").replaceAll("\\", "/");
  if (
    link.startsWith("/") ||
    link.startsWith("//") ||
    /^[a-zA-Z]:\//.test(link) ||
    link.split("/").some((part) => part === "." || part === "..")
  ) {
    throw new Error(`link must be a safe repository-relative path: ${value}`);
  }
  return link;
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!command || command === "--help" || command === "-h")
    return { command: "help" };
  if (command === "scan") {
    if (rest.length) throw new Error("scan takes no arguments");
    return { command };
  }
  if (command === "review" || command === "approve") {
    if (rest.length !== 1 || !/^\d{4}$/.test(rest[0])) {
      throw new Error(`${command} requires one NNNN argument`);
    }
    return { command, number: rest[0] };
  }
  if (command !== "add") throw new Error(`unknown command: ${command}`);

  const values = { links: [] };
  for (let index = 0; index < rest.length; index += 2) {
    const flag = rest[index];
    const value = rest[index + 1];
    if (!flag?.startsWith("--") || value === undefined)
      throw new Error(`invalid add argument: ${flag ?? ""}`);
    if (flag === "--link") values.links.push(value);
    else if (
      ["--title", "--context", "--decision", "--consequences"].includes(flag)
    ) {
      const key = flag.slice(2);
      if (values[key] !== undefined)
        throw new Error(`${flag} may be supplied once`);
      values[key] = requireText(value, key);
    } else throw new Error(`unknown add option: ${flag}`);
  }
  if (!values.links.length) throw new Error("add requires at least one --link");
  return { command, ...values };
}

function section(content, name) {
  const headings = [...content.matchAll(SECTION_RE)];
  const index = headings.findIndex((match) => match[1].trim() === name);
  if (index < 0) return "";
  const start = headings[index].index + headings[index][0].length;
  const end = headings[index + 1]?.index ?? content.length;
  return content.slice(start, end).trim();
}

function linksFrom(content) {
  return section(content, "Links")
    .split("\n")
    .map((line) =>
      line
        .trim()
        .match(/^-\s+`?([^`]+?)`?\s*$/)?.[1]
        ?.trim(),
    )
    .filter(Boolean);
}

function parseDecision(name, content) {
  const match = FILE_RE.exec(name);
  if (!match)
    return {
      name,
      invalidName: true,
      number: "",
      slug: "",
      title: "",
      status: "unknown",
    };
  const title =
    content.match(/^#\s+\d{4}(?:\s*[.—]\s*)(.+)$/m)?.[1]?.trim() ?? "";
  const rawStatus = (
    content.match(/^\*\*Status:\*\*\s*([a-z-]+)\s*$/im)?.[1] ??
    section(content, "Status").match(/^([a-z-]+)\s*$/i)?.[1] ??
    "unknown"
  ).toLowerCase();
  return {
    name,
    number: match[1],
    slug: match[2],
    title,
    status: VALID_STATUSES.has(rawStatus) ? rawStatus : "unknown",
    context: section(content, "Context"),
    decision: section(content, "Decision"),
    consequences: section(content, "Consequences"),
    links: linksFrom(content),
    content,
  };
}

async function scanDocuments() {
  let names;
  try {
    names = await fs.readdir(decisionsDir);
  } catch (error) {
    if (error.code === "ENOENT") return [];
    throw error;
  }
  const docs = [];
  for (const name of names.sort()) {
    if (name === "README.md" || name.startsWith(".")) continue;
    if (!name.endsWith(".md")) continue;
    const content = await fs.readFile(path.join(decisionsDir, name), "utf8");
    docs.push(parseDecision(name, content));
  }
  return docs;
}

function reviewDecision(doc) {
  const checks = {
    "name and number": !doc.invalidName && /^\d{4}$/.test(doc.number),
    status: VALID_STATUSES.has(doc.status),
    context: Boolean(doc.context),
    decision: Boolean(doc.decision),
    consequences: Boolean(doc.consequences),
    links:
      doc.links.length > 0 &&
      doc.links.every((link) => {
        try {
          safeLink(link);
          return true;
        } catch {
          return false;
        }
      }),
  };
  return { checks, score: Object.values(checks).filter(Boolean).length };
}

function renderDecision(input, number) {
  return `# ${number} — ${input.title}\n\n**Status:** proposed\n\n## Context\n\n${input.context}\n\n## Decision\n\n${input.decision}\n\n## Consequences\n\n${input.consequences}\n\n## Links\n\n${input.links.map((link) => `- \`${link}\``).join("\n")}\n`;
}

function renderIndex(existing, doc) {
  const row = `| ${doc.number} | ${doc.title} | ${doc.status} |`;
  const lines = existing
    ? existing.replace(/\r\n/g, "\n").split("\n")
    : ["# Decision Log", ""];
  const header = lines.findIndex((line) => /^\|\s*NNNN\s*\|/i.test(line));
  if (header < 0) {
    return `${lines.join("\n").replace(/\n*$/, "")}\n\n| NNNN | Заголовок | Статус |\n| --- | --- | --- |\n${row}\n`;
  }
  let end = header + 2;
  while (end < lines.length && /^\|/.test(lines[end])) end += 1;
  const current = lines
    .slice(header + 2, end)
    .filter((line) => !new RegExp(`^\\|\\s*${doc.number}\\s*\\|`).test(line));
  current.push(row);
  current.sort((left, right) => left.localeCompare(right));
  lines.splice(header + 2, end - (header + 2), ...current);
  return `${lines.join("\n").replace(/\n*$/, "")}\n`;
}

async function readMaybe(target) {
  try {
    return await fs.readFile(target);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function writeStaged(target, content) {
  const temp = `${target}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  const handle = await fs.open(temp, "wx", 0o600);
  try {
    await handle.writeFile(content, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
  return temp;
}

async function restore(target, snapshot) {
  if (snapshot === null)
    await fs.unlink(target).catch((error) => {
      if (error.code !== "ENOENT") throw error;
    });
  else await fs.writeFile(target, snapshot, { mode: 0o600 });
}

async function commit(changes) {
  await fs.mkdir(decisionsDir, { recursive: true });
  let lock;
  const staged = [];
  const snapshots = new Map();
  const changed = [];
  try {
    lock = await fs.open(lockPath, "wx", 0o600);
    await lock.writeFile(`${process.pid}\n`);
    await lock.sync();
    for (const { target } of changes)
      snapshots.set(target, await readMaybe(target));
    for (const { target, content } of changes)
      staged.push({ target, temp: await writeStaged(target, content) });
    for (let index = 0; index < staged.length; index += 1) {
      if (
        process.env.NODE_ENV === "test" &&
        process.env.DECISIONS_TEST_FAIL_RENAME_AT === String(index + 1)
      ) {
        throw new Error("injected rename failure");
      }
      await fs.rename(staged[index].temp, staged[index].target);
      changed.push(staged[index].target);
    }
  } catch (error) {
    for (const target of [...changed].reverse())
      await restore(target, snapshots.get(target));
    throw error;
  } finally {
    await Promise.all(
      staged.map(({ temp }) => fs.unlink(temp).catch(() => {})),
    );
    if (lock) await lock.close();
    await fs.unlink(lockPath).catch(() => {});
  }
}

function nextNumber(docs) {
  const numbers = docs
    .filter((doc) => !doc.invalidName)
    .map((doc) => Number(doc.number));
  return String((numbers.length ? Math.max(...numbers) : 0) + 1).padStart(
    4,
    "0",
  );
}

async function scan() {
  const docs = await scanDocuments();
  const seen = new Set();
  let valid = true;
  for (const doc of docs) {
    const duplicate = doc.number && seen.has(doc.number);
    if (doc.number) seen.add(doc.number);
    const state = doc.invalidName
      ? "invalid-name"
      : duplicate
        ? "duplicate-number"
        : doc.status;
    process.stdout.write(
      `${doc.name}: ${doc.title || "(untitled)"} [${state}]\n`,
    );
    valid &&= !doc.invalidName && !duplicate && VALID_STATUSES.has(doc.status);
  }
  if (!valid)
    process.stderr.write("Decision journal has invalid or legacy entries.\n");
  return valid;
}

async function review(number) {
  const doc = (await scanDocuments()).find((item) => item.number === number);
  if (!doc) throw new Error(`decision ${number} not found`);
  const result = reviewDecision(doc);
  for (const [name, passed] of Object.entries(result.checks))
    process.stdout.write(`${passed ? "PASS" : "FAIL"} ${name}\n`);
  process.stdout.write(`Score: ${result.score}/6\n`);
  return result.score >= 5;
}

async function add(input) {
  const validated = {
    title: requireText(input.title, "title"),
    context: requireText(input.context, "context"),
    decision: requireText(input.decision, "decision"),
    consequences: requireText(input.consequences, "consequences"),
    links: input.links.map(safeLink),
  };
  const slug = slugify(validated.title);
  const docs = await scanDocuments();
  if (docs.some((doc) => doc.invalidName))
    throw new Error(
      "cannot add while journal contains an invalid decision filename",
    );
  const number = nextNumber(docs);
  const doc = { number, title: validated.title, status: "proposed" };
  const existing = (await readMaybe(readmePath))?.toString("utf8") ?? "";
  await commit([
    {
      target: path.join(decisionsDir, `${number}-${slug}.md`),
      content: renderDecision(validated, number),
    },
    { target: readmePath, content: renderIndex(existing, doc) },
  ]);
  process.stdout.write(`Created ${number}-${slug}.md [proposed]\n`);
}

async function approve(number) {
  const docs = await scanDocuments();
  const doc = docs.find((item) => item.number === number);
  if (!doc) throw new Error(`decision ${number} not found`);
  if (doc.status !== "proposed")
    throw new Error(`decision ${number} must be proposed before approval`);
  const result = reviewDecision(doc);
  if (result.score < 5)
    throw new Error(`decision ${number} review failed: ${result.score}/6`);
  const updated = doc.content.replace(
    /^\*\*Status:\*\*\s*proposed\s*$/im,
    "**Status:** accepted",
  );
  const existing = (await readMaybe(readmePath))?.toString("utf8") ?? "";
  await commit([
    { target: path.join(decisionsDir, doc.name), content: updated },
    {
      target: readmePath,
      content: renderIndex(existing, { ...doc, status: "accepted" }),
    },
  ]);
  process.stdout.write(`Approved ${number} [accepted]\n`);
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (error) {
    fail(`${error.message}\n\n${HELP}`, 2);
    return;
  }
  try {
    if (args.command === "help") process.stdout.write(`${HELP}\n`);
    else if (args.command === "scan") {
      if (!(await scan())) process.exitCode = 1;
    } else if (args.command === "review") {
      if (!(await review(args.number))) process.exitCode = 1;
    } else if (args.command === "add") await add(args);
    else if (args.command === "approve") await approve(args.number);
  } catch (error) {
    fail(error.message);
  }
}

await main();
