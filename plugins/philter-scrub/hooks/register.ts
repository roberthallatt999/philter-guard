import type { EngineInterface, Register } from 'claude-code'

// The Philter MCP server as /mcp lists it. Calls go through Claude Code's own
// connection, so this mod never holds the Philter API key.
const SERVER = 'philter'

// Fails closed: if Philter can't be reached, the prompt is not sent and the
// tool result is withheld, rather than letting raw text through.
let isOn = true
let allowImages = false
let total = 0

// Tools whose output is only a confirmation of what Claude itself wrote.
const SKIP_TOOLS = new Set(['Edit', 'Write', 'MultiEdit', 'NotebookEdit', 'TodoWrite'])
// Source code is read unscrubbed so Claude can edit it (an edit has to match the
// real text). Everything else a file read returns (logs, CSV, JSON, dumps, text,
// unknown types) is treated as data and scrubbed. Command output, search results,
// web pages and connector results are always scrubbed.
const CODE_FILE =
  /\.(?:ts|tsx|js|jsx|mjs|cjs|d\.ts|py|rb|php|go|rs|java|kt|kts|swift|c|h|cc|cpp|hpp|cs|m|scala|lua|pl|sh|bash|zsh|fish|ps1|css|scss|sass|less|html|htm|vue|svelte|astro|twig|blade\.php|erb|md|mdx|toml|ini|gradle|dockerfile|tf|graphql|gql|proto|lock)$|(?:^|\/)(?:Dockerfile|Makefile|Gemfile|Rakefile|\.gitignore|\.editorconfig)$/i
const isCodeRead = (e: { tool: string; file_path?: unknown }) =>
  e.tool === 'Read' && typeof e.file_path === 'string' && CODE_FILE.test(e.file_path)

// Images, PDFs and other non-text content Philter can't read.
const NON_TEXT = /"type"\s*:\s*"(?:image|pdf|document|audio)"/

type Scrubbed = { text: string; count: number }

// Per-project policy: the first non-comment line of a `.philter` file names a
// Philter policy set. Chosen once per session; the base policy is used when
// there is no file or the set can't be used.
const SET_NAME = /^[a-z0-9][a-z0-9-]*$/
const SET_PREFIX = 'set-'
// Tool output goes through the "code" variant of the same policy (code-comprehensive,
// code-set-<name>), which sync-policy.sh builds without the shape-only filters that hit
// hashes, UUIDs and build ids. Prompts keep the prose policy. Falls back to `policy` when
// the server doesn't list the code variant (not synced yet, or the list can't be read).
const CODE_PREFIX = 'code-'
let policy: string | undefined
let codePolicy: string | undefined
let policyNote = ''

export function parseSetName(text: string): string | null {
  for (const raw of text.replace(/^﻿/, '').split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith('#')) continue
    return SET_NAME.test(line) ? line : null
  }
  return null
}

// Looks for <dir>/.philter from cwd upward, stopping after the first dir that
// holds a git marker, or at the root.
export async function findPhilterFile($: EngineInterface, cwd: string): Promise<string | null> {
  let dir = cwd.length > 1 ? cwd.replace(/\/+$/, '') || '/' : cwd
  for (;;) {
    const base = dir === '/' ? '' : dir
    if (await $.fs.exists(base + '/.philter')) return base + '/.philter'
    if (dir === '/' || (await $.fs.exists(base + '/.git'))) return null
    const up = dir.replace(/\/[^/]*$/, '') || '/'
    if (up === dir) return null // relative or odd path with nothing left to strip
    dir = up
  }
}

// The live tool nests the array two levels down ({policies: {policies: [...], total}}),
// and items may be strings or {name}. Search to a small depth for the first array.
function findNames(v: unknown, depth: number): string[] | null {
  if (Array.isArray(v))
    return v
      .map((x: unknown) => (typeof x === 'string' ? x : (x as { name?: unknown } | null)?.name))
      .filter((x: unknown): x is string => typeof x === 'string')
  if (depth >= 4 || !v || typeof v !== 'object') return null
  for (const child of Object.values(v as object)) {
    const found = findNames(child, depth + 1)
    if (found) return found
  }
  return null
}

// What a person sees when Philter can't be used: names the policy if one is active.
const why = (use: string | undefined = policy) =>
  use
    ? `Philter rejected policy ${use} (is it synced? run sync-policy.sh)`
    : 'Philter could not be reached'

// null when the list can't be fetched or understood.
async function listPolicies($: EngineInterface): Promise<string[] | null> {
  try {
    const res = await $.mcp.call(SERVER, 'list_policies', {})
    const block = res.content.find((b: { type: string }) => b.type === 'text') as { text?: string } | undefined
    if (res.isError || !block?.text) return null
    const body = JSON.parse(block.text) as unknown
    const arr = findNames(body, 0)
    if (!arr || arr.length === 0) return null // empty or unrecognised: unknown, not "none"
    return arr
  } catch {
    return null
  }
}

async function resolvePolicy($: EngineInterface, cwd: string) {
  policy = undefined
  codePolicy = undefined
  policyNote = ''
  const names = await listPolicies($)
  await resolveProsePolicy($, cwd, names)
  const code = CODE_PREFIX + (policy ?? 'comprehensive')
  codePolicy = names && names.includes(code) ? code : policy
}

async function resolveProsePolicy($: EngineInterface, cwd: string, names: string[] | null) {
  let name: string | null
  try {
    const file = await findPhilterFile($, cwd)
    if (!file) return
    name = parseSetName(await $.fs.read(file))
  } catch {
    name = null
  }
  if (!name) {
    policyNote = '⚠ .philter unreadable or invalid, using base'
    return
  }
  if (name === 'comprehensive') return // the base itself: no argument needed
  // A repo can only select a policy that sync-policy.sh built, which always holds the
  // base rules: those are uploaded as set-<name>. The bare name is never sent.
  const server = SET_PREFIX + name
  if (names && !names.includes(server)) {
    policyNote = `⚠ policy "${name}" not found, using base`
    return
  }
  // If the list failed, still send it: an unknown name makes Philter error, which fails closed.
  policy = server
}

// Random IDs (UUIDs, Claude Docs tab and node ids like "be1476b2-62c1", the id at the end of a
// claude.ai artifact link) hold no personal data, but their digit runs look like phone, card and
// tracking numbers to Philter: a Docs node id "ce" + 10 digits came back as a phone number, so the
// doc couldn't be written to. A policy ignore rule can't fix this, because Philter checks it
// against the matched span ("6135550199") alone, never the ID around it. So IDs are swapped for
// letter-only tokens before Philter sees the text and put back after. A match with no letter is
// left for Philter: an all-digit "ID" could be a real account or phone number.
const RANDOM_ID = new RegExp(
  [
    String.raw`\b[0-9a-f]{8}-[0-9a-f]{4}(?:-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})?\b`,
    String.raw`(?<=claude\.ai\/(?:code\/)?artifact\/(?:[\w-]*-)?)[A-Za-z0-9]{22}\b`,
  ].join('|'),
  'gi',
)
const TOKEN_MARK = 'KEEPID'
const TOKEN = /KEEPID([A-Z]+)x/g

// 0 → "A", 25 → "Z", 26 → "BA": letters only, so no Philter filter reads it as a number.
const toLetters = (n: number): string => (n < 26 ? '' : toLetters(Math.floor(n / 26))) + String.fromCharCode(65 + (n % 26))
const fromLetters = (s: string): number => [...s].reduce((n, c) => n * 26 + c.charCodeAt(0) - 65, 0)

/**
 * Swaps random IDs in text for placeholder tokens.
 * @param text the text about to be scrubbed
 * @returns the text with tokens, and the IDs in token order. Text that already holds the token
 *   marker is returned unchanged, so a restore can never put an ID where none was.
 * @example protectIds('node "be1476b2-62c1"') // { text: 'node "KEEPIDAx"', ids: ['be1476b2-62c1'] }
 */
export function protectIds(text: string): { text: string; ids: string[] } {
  const ids: string[] = []
  if (text.includes(TOKEN_MARK)) return { text, ids }
  const swapped = text.replace(RANDOM_ID, id => {
    if (!/[a-z]/i.test(id)) return id
    ids.push(id)
    return `${TOKEN_MARK}${toLetters(ids.length - 1)}x`
  })
  return { text: swapped, ids }
}

/** Puts back the IDs protectIds took out. A token Philter changed stays changed. */
export function restoreIds(text: string, ids: string[]): string {
  if (ids.length === 0) return text
  return text.replace(TOKEN, (token, letters: string) => ids[fromLetters(letters)] ?? token)
}

async function scrub($: EngineInterface, original: string, use: string | undefined = policy): Promise<Scrubbed> {
  const { text, ids } = protectIds(original)
  const res = await $.mcp.call(SERVER, 'redact_text', use ? { text, policy: use } : { text })
  const block = res.content.find((b: { type: string }) => b.type === 'text') as { text?: string } | undefined
  if (res.isError || !block?.text) throw new Error('Philter returned no result')
  const body = JSON.parse(block.text) as { filtered_text?: string; redaction_count?: number; error?: string }
  if (body.error || typeof body.filtered_text !== 'string') throw new Error(body.error ?? 'Philter returned no text')
  return { text: restoreIds(body.filtered_text, ids), count: body.redaction_count ?? 0 }
}

function showCount($: EngineInterface, added: number) {
  total += added
  $.ui.status(
    (isOn ? `🛡 Philter: ${total} redacted${allowImages ? ' · images ALLOWED' : ''}` : '🛡 Philter: OFF') +
      (policy ? ` · set ${policy.slice(SET_PREFIX.length)}` : '') +
      (policyNote ? ` · ${policyNote}` : ''),
  )
}

type Rec = Record<string, unknown>
const isRec = (v: unknown): v is Rec => !!v && typeof v === 'object' && !Array.isArray(v)

// Bash only: its text is stdout and stderr, so the scrubbed text can replace both. Fields that
// could carry unscrubbed text another way (structured blocks, a path to the raw output, a
// background task's file) make it a deny. Read, Grep, web and MCP results keep the deny: their
// model-facing text is built by each tool's mapper, and a wrong rewrite could leak or mangle it.
export function rewriteResult(tool: string, result: unknown, text: string, note: string): Rec | null {
  if (!isRec(result)) return null
  if (tool === 'Bash') {
    if (typeof result.stdout !== 'string' || typeof result.stderr !== 'string') return null
    if (result.isImage || result.structuredContent !== undefined || result.persistedOutputPath !== undefined
      || result.rawOutputPath !== undefined || result.backgroundTaskId !== undefined) return null
    return { ...result, stdout: `${text}\n${note}`, stderr: '' }
  }
  return null
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'scrub',
      description:
        'Philter scrubbing: "/scrub on|off", "/scrub images on|off" (images can\'t be redacted), or "/scrub" for status',
    })
    await resolvePolicy($, e.cwd)
    showCount($, 0)
    return next(e)
  })

  on('command.run', { command: 'scrub' }, async ($, e) => {
    const arg = (e.args ?? '').trim().toLowerCase().replace(/\s+/g, ' ')
    if (arg === 'off') isOn = false
    if (arg === 'on') isOn = true
    if (arg === 'images on') allowImages = true
    if (arg === 'images off') allowImages = false
    showCount($, 0)
    const images = allowImages
      ? 'Images and PDFs are ALLOWED through unredacted.'
      : 'Images and PDFs are BLOCKED ("/scrub images on" to allow).'
    return {
      text: isOn
        ? `Philter scrubbing is ON. ${total} items redacted this session. ${images} Policy: ${policy ? `${policy.slice(SET_PREFIX.length)} (${policy})` : 'base (comprehensive)'}. Tool output: ${codePolicy ?? 'comprehensive'}.${policyNote ? ` ${policyNote}.` : ''}`
        : 'Philter scrubbing is OFF. Prompts, tool results and images go to the model unredacted.',
    }
  })

  // What you type. Slash commands are left alone (their text can't be rewritten here).
  on('prompt.submit', async ($, e, next) => {
    if (!isOn || e.command) return next(e)
    if (!allowImages && e.attachments?.length) {
      const n = e.attachments.length
      const what = n === 1 ? 'a screenshot or file' : `${n} screenshots or files`
      let choice = ''
      try {
        choice = await $.ui.ask(
          `This message has ${what} that Philter can't redact. Check it has no customer data. Send it anyway?`,
          { header: 'Screenshot', options: ['Send it', "Don't send", 'Allow for this session'] },
        )
      } catch {
        choice = "Don't send" // dismissed, or no one to ask
      }
      if (choice === 'Allow for this session') {
        allowImages = true
        showCount($, 0)
      } else if (choice !== 'Send it') {
        return { drop: 'Not sent. Your message had an image or file Philter can\'t redact.' }
      }
    }
    if (!e.text.trim()) return next(e)
    const { text, count } = await scrub($, e.text)
    showCount($, count)
    if (count > 0) $.ui.toast(`Philter redacted ${count} item${count === 1 ? '' : 's'} from your message`)
    return next({ ...e, text })
  }).catch(($, e, next) =>
    next.called
      ? next(e)
      : { drop: `${why()}, so the message was not sent. Check that the philter containers are running, or turn scrubbing off with /scrub off.` },
  )

  // What tools hand back (file reads, command output, web pages, other MCP servers).
  on('tool.call', async ($, e, next) => {
    if (!isOn || e.tool.startsWith('mcp__philter__') || SKIP_TOOLS.has(e.tool) || isCodeRead(e as never))
      return next(e)
    const ran = await next(e)
    if (ran.deny !== undefined) return ran
    if (!allowImages && NON_TEXT.test(JSON.stringify(ran.result ?? null))) {
      return {
        deny: 'Result withheld: it contains an image or document, which Philter can\'t redact. The person can allow these with /scrub images on.',
      }
    }
    const raw = ran.text
    if (!raw || !raw.trim()) return ran
    let out: Scrubbed
    try {
      out = await scrub($, raw, codePolicy)
    } catch {
      return { deny: `Result withheld: ${why(codePolicy)}, so it could not be redacted.` }
    }
    if (out.count === 0) return ran
    showCount($, out.count)
    const note = `[Philter redacted ${out.count} item${out.count === 1 ? '' : 's'}]`
    // Hand back an ordinary result with placeholders where the shape allows it, so a single
    // redaction doesn't read as an error ("a plugin withheld its result"). Anything else is
    // withheld as before.
    const rewritten = rewriteResult(e.tool, ran.result, out.text, note)
    if (rewritten !== null) return { result: rewritten as never }
    return { deny: `${note}\n${out.text}` }
  }).catch(($, e, next) =>
    next.called ? { deny: 'Result withheld: the Philter scrub hook failed.' } : next(e),
  )
}
