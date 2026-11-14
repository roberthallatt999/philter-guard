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
