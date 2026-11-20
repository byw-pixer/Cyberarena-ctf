// Firefox WebDriver BiDi, Node with its built-in WebSocket, and a disposable stack.
import assert from 'node:assert/strict'

const [port, base] = process.argv.slice(2)
assert.match(port, /^[0-9]+$/)
assert.match(base, /^http:\/\/127\.0\.0\.1:[0-9]+$/)
assert.notEqual(new URL(base).port, '8080')
const ws = new WebSocket('ws://127.0.0.1:' + port + '/session')
await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject })
let id = 0
const pending = new Map()
ws.onmessage = ({data}) => {
  const message = JSON.parse(data)
  const entry = pending.get(message.id)
  if (!entry) return
  pending.delete(message.id)
  if (message.type === 'error') entry.reject(Error(message.error + ': ' + message.message))
  else entry.resolve(message.result)
}
const send = (method, params = {}) => new Promise((resolve, reject) => {
  pending.set(++id, {resolve, reject})
  ws.send(JSON.stringify({id, method, params}))
})

let sessionOpen = false
try {
  await send('session.new', {capabilities: {}})
  sessionOpen = true
  const {context} = await send('browsingContext.create', {type: 'tab'})
  const evaluate = async expression => (await send('script.evaluate', {
    expression, target: {context}, awaitPromise: true
  })).result?.value
  const open = path => send('browsingContext.navigate', {context, url: base + path, wait: 'complete'})
  const viewport = width => send('browsingContext.setViewport', {context, viewport: {width, height: 844}})
  const field = (selector, value) => evaluate(
    'document.querySelector(' + JSON.stringify(selector) + ').value=' + JSON.stringify(value))
  const submit = async action => {
    await evaluate('setTimeout(() => document.querySelector(' +
      JSON.stringify('form[action="' + action + '"]') + ').requestSubmit(), 0); true')
  }
  async function waitUntil(expression) {
    for (let attempt = 0; attempt < 80; attempt++) {
      if (await evaluate(expression)) return
      await new Promise(resolve => setTimeout(resolve, 100))
    }
    throw Error('Browser condition timed out: ' + expression)
  }
  async function inspect(path, width) {
    await open(path)
    assert.equal(await evaluate('location.pathname'), path)
    assert.equal(await evaluate('innerWidth'), width)
    const scroll = await evaluate('document.documentElement.scrollWidth')
    assert(scroll <= width, path + ' scroll width ' + scroll + ' at ' + width)
    if (path === '/admin' && width <= 390) {
      assert(await evaluate("(() => { const table = document.querySelector('.admin-table-wrap'); return table.scrollWidth > table.clientWidth && getComputedStyle(table).overflowX === 'auto'; })()"))
    }
  }

  await viewport(390)
  await open('/register')
  assert(await evaluate("document.querySelector('#menuToggle').click(); document.querySelector('#sidebar').classList.contains('open')"))
  assert(await evaluate("document.querySelector('#scrim').click(); !document.querySelector('#sidebar').classList.contains('open')"))
  const username = 'browser_' + Date.now()
  await field('#username', username)
  await field('#password', 'disposable-browser-fixture-password')
  await submit('/register')
  await waitUntil("location.pathname === '/profile'")
  for (const width of [320, 390, 768, 1366, 1920]) {
    await viewport(width)
    for (const path of ['/register', '/login', '/profile', '/challenges', '/challenges/1', '/leaderboard']) {
      await inspect(path, width)
    }
    console.log('PASS player pages at', width, 'px')
  }
  await inspect('/login', 1920)
  await field('#username', username)
  await field('#password', 'different-disposable-browser-password')
  await submit('/login')
  await waitUntil("document.querySelector('[role=alert]')?.textContent.includes('Неверный логин')")
  assert.equal(await evaluate("document.querySelector('#username').value"), username)
  assert.equal(await evaluate("document.querySelector('#password').value"), '')
  assert(process.env.BROWSER_TEACHER && process.env.BROWSER_TEACHER_PASSWORD)
  await field('#username', process.env.BROWSER_TEACHER)
  await field('#password', process.env.BROWSER_TEACHER_PASSWORD)
  await submit('/login')
  await waitUntil("location.pathname === '/profile'")
  for (const width of [320, 390, 768, 1366, 1920]) {
    await viewport(width)
    await inspect('/admin', width)
    console.log('PASS administration at', width, 'px')
  }
  console.log('PASS browser registration, mobile menu and HTML error with safe field retention')
} finally {
  if (sessionOpen) await send('session.end')
  ws.close()
}
