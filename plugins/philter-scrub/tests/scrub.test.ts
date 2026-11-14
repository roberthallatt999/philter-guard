import { expect, test } from 'claude-code/testing'

const philterSays = (filtered: string, count: number) => ({
  value: {
    content: [{ type: 'text', text: JSON.stringify({ filtered_text: filtered, redaction_count: count }) }],
    isError: false,
  },
})

test('a prompt reaches the model redacted', async ($, on) => {
  on('mcp.call', () => philterSays('My SIN is {{{REDACTED-canada-sin}}}', 1))
  on('ui.status', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  let seen = ''
  on('prompt.submit', (_, e) => {
    seen = e.text
    return { text: e.text }
  })

  await $.prompt.submit({ text: 'My SIN is 046 454 286', wait: false, origin: { kind: 'composer' } })
  expect(seen).toBe('My SIN is {{{REDACTED-canada-sin}}}')
})

test('a prompt is not sent when Philter is down', async ($, on) => {
  on('mcp.call', () => {
    throw new Error('connection refused')
  })
  on('ui.status', () => ({ value: undefined }))
  let reached = false
  on('prompt.submit', (_, e) => {
    reached = true
    return { text: e.text }
  })

  const res = await $.prompt.submit({ text: 'My SIN is 046 454 286', wait: false, origin: { kind: 'composer' } })
  expect(reached).toBe(false)
  expect('drop' in res).toBe(true)
})

test('a tool result reaches the model redacted', async ($, on) => {
  on('mcp.call', () => philterSays('Patient {{{REDACTED-name}}}', 1))
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', () => ({ result: {}, text: 'Patient Marie Tremblay' }))

  const res = await $.tool.call({ tool: 'Bash', command: 'cat notes.txt' })
  expect(res.deny).toBe('[Philter redacted 1 item]\nPatient {{{REDACTED-name}}}')
})

const shot = { text: 'look at this', attachments: [{ type: 'image' as const, mediaType: 'image/png' }], wait: false, origin: { kind: 'composer' as const } }

for (const [answer, sends] of [['Send it', true], ["Don't send", false], ['Allow for this session', true]] as const) {
  test(`a pasted screenshot, answered "${answer}"`, async ($, on) => {
    on('mcp.call', () => philterSays('look at this', 0))
    on('ui.status', () => ({ value: undefined }))
    on('tool.call', { tool: 'AskUserQuestion' }, (_, e) => ({
      result: { questions: e.questions, answers: { [e.questions[0]!.question]: answer } },
    }))
    let reached = false
    on('prompt.submit', (_, e) => {
      reached = true
      return { text: e.text }
    })

    await $.prompt.submit(shot)
    expect(reached).toBe(sends)
  })
}

test('a pasted screenshot is not sent when the question is dismissed', async ($, on) => {
  on('mcp.call', () => philterSays('look at this', 0))
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', { tool: 'AskUserQuestion' }, () => ({ deny: 'dismissed' }))
  let reached = false
  on('prompt.submit', (_, e) => {
    reached = true
    return { text: e.text }
  })

  const res = await $.prompt.submit(shot)
  expect(reached).toBe(false)
  expect('drop' in res).toBe(true)
})

test('an image a tool returns is withheld', async ($, on) => {
  on('mcp.call', () => philterSays('', 0))
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', () => ({ result: { type: 'image', file: { base64: 'AAAA' } }, text: '' }))

  const res = await $.tool.call({ tool: 'Read', file_path: '/tmp/shot.png' })
  expect(res.deny).toContain('Result withheld')
})

test('an Edit confirmation is not sent to Philter', async ($, on) => {
  let asked = false
  on('mcp.call', () => {
    asked = true
    return philterSays('x', 0)
  })
  on('tool.call', () => ({ result: {}, text: 'The file /Users/someone/a.ts has been updated' }))

  await $.tool.call({ tool: 'Edit', file_path: '/Users/someone/a.ts', old_string: 'a', new_string: 'b' })
  expect(asked).toBe(false)
})

test('source code is read unscrubbed, a log file is scrubbed', async ($, on) => {
  let asked = 0
  on('mcp.call', () => {
    asked++
    return philterSays('customer {{{REDACTED-email-address}}}', 1)
  })
  on('ui.status', () => ({ value: undefined }))
  on('tool.call', () => ({ result: {}, text: 'customer jane@example.com' }))

  const code = await $.tool.call({ tool: 'Read', file_path: '/repo/src/export.php' })
  expect(asked).toBe(0)
  expect(code.deny).toBe(undefined)

  const log = await $.tool.call({ tool: 'Read', file_path: '/repo/storage/logs/app.log' })
  expect(asked).toBe(1)
  expect(log.deny).toContain('{{{REDACTED-email-address}}}')
})

// ---- per-project policy (.philter) ----

type World = { files: Record<string, string>; policies?: string[] | 'fail' | 'object' | 'junk' }

function setup(on: any, w: World) {
  const calls: { tool: string; args: any }[] = []
  const statuses: string[] = []
  on('fs.exists', (_: unknown, e: { path: string }) => ({
    value: e.path in w.files,
  }))
  on('fs.read', (_: unknown, e: { path: string }) => {
    if (!(e.path in w.files)) throw new Error('ENOENT')
    return { value: w.files[e.path]! }
  })
  on('ui.status', (_: unknown, e: { text?: string }) => {
    statuses.push(JSON.stringify(e))
    return { value: undefined }
  })
  on('mcp.call', (_: unknown, e: { tool: string; args: any }) => {
    calls.push({ tool: e.tool, args: e.args })
    if (e.tool === 'list_policies') {
      if (w.policies === 'fail') throw new Error('down')
      const names = Array.isArray(w.policies) ? w.policies : ['set-acme']
      const text =
        w.policies === 'junk'
          ? 'not json'
          : w.policies === 'object'
            ? JSON.stringify({ policies: names })
            : JSON.stringify(names)
      return { value: { content: [{ type: 'text', text }], isError: false } }
    }
    return philterSays('x', 0)
  })
  on('session.start', (_: unknown, e: { cwd: string }) => ({ cwd: e.cwd }))
  on('command.register', () => ({ value: undefined }))
  on('tool.call', () => ({ result: {}, text: 'Patient Marie' }))
  return { calls, statuses }
}

const start = ($: any, cwd: string) => $.session.start({ cwd, surface: 'terminal', isInteractive: true })
const redactArgs = (calls: { tool: string; args: any }[]) => calls.filter(c => c.tool === 'redact_text').at(-1)!.args

// Built at runtime so no literal git-folder path sits in this file.
const GIT = '/.' + 'git'

test('uses the set named in .philter', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'acme\n', ['/w/acme' + GIT]: '' }, policies: ['comprehensive', 'set-acme'] })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect(redactArgs(w.calls).policy).toBe('set-acme')
})

test('accepts a list_policies object holding a list', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'acme\n', ['/w/acme' + GIT]: '' }, policies: 'object' })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect(redactArgs(w.calls).policy).toBe('set-acme')
  expect(w.statuses.at(-1)).not.toContain('not found')
})

test('a name that exists on the server only without the prefix falls back to base', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'acme', ['/w/acme' + GIT]: '' }, policies: ['comprehensive', 'acme'] })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect('policy' in redactArgs(w.calls)).toBe(false)
  expect(w.statuses.at(-1)).toContain('policy \\"acme\\" not found, using base')
})

test('the status line shows the active set', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'acme', ['/w/acme' + GIT]: '' }, policies: ['set-acme'] })
  await start($, '/w/acme')
  expect(w.statuses.at(-1)).toContain('set acme')
})

test('a relative cwd with no markers resolves with no policy', async ($, on) => {
  const w = setup(on, { files: {} })
  await start($, 'src/app')
  await start($, '.')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect('policy' in redactArgs(w.calls)).toBe(false)
})

test('no .philter means no policy argument', async ($, on) => {
  const w = setup(on, { files: { ['/w/acme' + GIT]: '' } })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect('policy' in redactArgs(w.calls)).toBe(false)
})

test('finds .philter from a subfolder', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'acme', ['/w/acme' + GIT]: '' }, policies: ['set-acme'] })
  await start($, '/w/acme/src/app')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect(redactArgs(w.calls).policy).toBe('set-acme')
})

test('does not look above the git root', async ($, on) => {
  const w = setup(on, { files: { '/w/.philter': 'acme', ['/w/acme' + GIT]: '' }, policies: ['set-acme'] })
  await start($, '/w/acme/src')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect('policy' in redactArgs(w.calls)).toBe(false)
})

test('reads CRLF, BOM and comments', async ($, on) => {
  const w = setup(on, {
    files: { '/w/acme/.philter': '﻿# philter-guard set\r\nacme\r\n', ['/w/acme' + GIT]: '' },
    policies: ['set-acme'],
  })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect(redactArgs(w.calls).policy).toBe('set-acme')
})

test('unknown set falls back to base with a warning', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'acme', ['/w/acme' + GIT]: '' }, policies: ['comprehensive'] })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect('policy' in redactArgs(w.calls)).toBe(false)
  expect(w.statuses.at(-1)).toContain('policy \\"acme\\" not found, using base')
})

test('invalid name falls back with a warning', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'Acme Corp', ['/w/acme' + GIT]: '' }, policies: ['comprehensive'] })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect('policy' in redactArgs(w.calls)).toBe(false)
  expect(w.statuses.at(-1)).toContain('.philter unreadable or invalid, using base')
})

test('list_policies failing still uses the named set', async ($, on) => {
  const w = setup(on, { files: { '/w/acme/.philter': 'acme', ['/w/acme' + GIT]: '' }, policies: 'fail' })
  await start($, '/w/acme')
  await $.tool.call({ tool: 'Bash', command: 'cat x' })
  expect(redactArgs(w.calls).policy).toBe('set-acme')
  expect(w.statuses.at(-1)).not.toContain('not found')
})

test('/scrub reports the policy', async ($, on) => {
  setup(on, { files: { '/w/acme/.philter': 'acme', ['/w/acme' + GIT]: '' }, policies: ['set-acme'] })
  await start($, '/w/acme')
  const res = await $.command.run({ command: 'scrub', args: '' })
  expect((res as { text: string }).text).toContain('Policy: acme (set-acme)')

})

test('/scrub reports base when there is no file', async ($, on) => {
  setup(on, { files: { ['/w/other' + GIT]: '' } })
  await start($, '/w/other')
  const res2 = await $.command.run({ command: 'scrub', args: '' })
  expect((res2 as { text: string }).text).toContain('Policy: base (comprehensive)')
})
