import assert from 'node:assert/strict'
import childProcess from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test, type TestContext } from 'node:test'
import { AuthHelper } from '../../src/host/auth.ts'
import { sandboxEnv } from '../helpers/sandbox-env.ts'

function startAuth(t: TestContext) {
  const dir = mkdtempSync(join(tmpdir(), 'agy-auth-buffer-'))
  const restore = sandboxEnv(dir)
  const script = join(dir, 'agy.mjs')
  writeFileSync(script, 'process.stdin.resume()\n')
  const browser = t.mock.method(childProcess, 'execFile', () => {
    throw new Error('Browser launch disabled in offline auth tests')
  })
  syncBuiltinESMExports()
  const helper = new AuthHelper(() => script, () => false)
  const pending = helper.begin()
  // Inject separate pipe events deterministically, without OS write coalescing.
  const probe = helper['probe']!
  t.after(async () => {
    helper.dispose()
    await pending
    await probe.outcome
    browser.mock.restore()
    syncBuiltinESMExports()
    restore()
    rmSync(dir, { recursive: true, force: true })
  })
  return { pending, child: probe.child, helper }
}

const url = 'https://accounts.google.com/o/oauth2/auth?client_id=test&state=offline'

test('auth captures a consent URL from a raw stderr Buffer without throwing', { timeout: 5_000 }, async (t) => {
  const { pending, child } = startAuth(t)
  child.stderr!.emit('data', Buffer.from(`Sign in: (${url}).\r\n`))
  assert.equal((await pending).url, url)
})

for (const split of [20, url.indexOf('state=') + 'state='.length + 2]) {
  test(`auth preserves a stderr consent URL split at byte ${split}`, { timeout: 5_000 }, async (t) => {
    const { pending, child } = startAuth(t)
    child.stderr!.emit('data', Buffer.from('Sign in: ' + url.slice(0, split)))
    child.stderr!.emit('data', Buffer.from(url.slice(split) + '\n'))
    assert.equal((await pending).url, url)
  })
}

test('auth flushes a stderr consent URL without a final newline at EOF', { timeout: 5_000 }, async (t) => {
  const { pending, child } = startAuth(t)
  child.stderr!.emit('data', Buffer.from(url))
  child.stderr!.emit('end')
  assert.equal((await pending).url, url)
})

test('a superseded probe cannot capture its stderr tail in the new login flow', { timeout: 5_000 }, async (t) => {
  const { child: oldChild, helper } = startAuth(t)
  oldChild.stderr!.emit('data', Buffer.from(url))
  const pending = helper.begin()
  const probe = helper['probe']!
  t.after(async () => {
    helper.dispose()
    await pending
    await probe.outcome
  })
  oldChild.stderr!.emit('end')
  const nextUrl = 'https://accounts.google.com/o/oauth2/auth?client_id=test&state=new-login'
  probe.child.stderr!.emit('data', Buffer.from(nextUrl + '\n'))
  assert.equal((await pending).url, nextUrl)
})

test('auth still captures a consent URL from decoded stdout lines', { timeout: 5_000 }, async (t) => {
  const { pending, child } = startAuth(t)
  child.stdout!.emit('data', Buffer.from(url + '\n'))
  assert.equal((await pending).url, url)
})
