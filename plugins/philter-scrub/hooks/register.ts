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
let policy: string | undefined
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

// null when the list can't be fetched or understood.
async function listPolicies($: EngineInterface): Promise<string[] | null> {
  try {
    const res = await $.mcp.call(SERVER, 'list_policies', {})
    const block = res.content.find((b: { type: string }) => b.type === 'text') as { text?: string } | undefined
    if (res.isError || !block?.text) return null
    const body = JSON.parse(block.text) as unknown
    const arr = Array.isArray(body)
      ? body
      : body && typeof body === 'object'
        ? Object.values(body as object).find(Array.isArray)
        : undefined
    if (!arr) return null
    return arr
      .map((x: unknown) => (typeof x === 'string' ? x : (x as { name?: unknown } | null)?.name))
      .filter((x: unknown): x is string => typeof x === 'string')
  } catch {
    return null
  }
}

async function resolvePolicy($: EngineInterface, cwd: string) {
  policy = undefined
  policyNote = ''
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
  const names = await listPolicies($)
  if (names && !names.includes(server)) {
    policyNote = `⚠ policy "${name}" not found, using base`
    return
  }
  // If the list failed, still send it: an unknown name makes Philter error, which fails closed.
  policy = server
}

async function scrub($: EngineInterface, text: string): Promise<Scrubbed> {
  const res = await $.mcp.call(SERVER, 'redact_text', policy ? { text, policy } : { text })
  const block = res.content.find((b: { type: string }) => b.type === 'text') as { text?: string } | undefined
  if (res.isError || !block?.text) throw new Error('Philter returned no result')
  const body = JSON.parse(block.text) as { filtered_text?: string; redaction_count?: number; error?: string }
  if (body.error || typeof body.filtered_text !== 'string') throw new Error(body.error ?? 'Philter returned no text')
  return { text: body.filtered_text, count: body.redaction_count ?? 0 }
}

function showCount($: EngineInterface, added: number) {
  total += added
  $.ui.status(
    (isOn ? `🛡 Philter: ${total} redacted${allowImages ? ' · images ALLOWED' : ''}` : '🛡 Philter: OFF') +
      (policy ? ` · set ${policy.slice(SET_PREFIX.length)}` : '') +
      (policyNote ? ` · ${policyNote}` : ''),
  )
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
        ? `Philter scrubbing is ON. ${total} items redacted this session. ${images} Policy: ${policy ? `${policy.slice(SET_PREFIX.length)} (${policy})` : 'base (comprehensive)'}.${policyNote ? ` ${policyNote}.` : ''}`
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
      : { drop: 'Philter could not be reached, so the message was not sent. Check that the philter containers are running, or turn scrubbing off with /scrub off.' },
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
      out = await scrub($, raw)
    } catch {
      return { deny: 'Result withheld: Philter could not be reached to redact it.' }
    }
    if (out.count === 0) return ran
    showCount($, out.count)
    return { deny: `[Philter redacted ${out.count} item${out.count === 1 ? '' : 's'}]\n${out.text}` }
  }).catch(($, e, next) =>
    next.called ? { deny: 'Result withheld: the Philter scrub hook failed.' } : next(e),
  )
}
